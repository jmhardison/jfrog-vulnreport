// Package internal — Xray and Artifactory SDK service wrappers.
//
// XrayService wraps jfroghttpclient.JfrogHttpClient for Xray API calls.
// ArtifactoryService wraps jfroghttpclient.JfrogHttpClient for Artifactory API calls.
// Both mirror jfrog-client-go's XscInnerService pattern: an authenticated HTTP client
// paired with ServiceDetails for header construction.
//
// NOTE: There is no typed SDK method for synchronous reads of /api/v1/violations in
// jfrog-client-go@v1.55.0. XrayService.GetViolations uses SendPost directly against
// /api/v1/violations (mirrors XscInnerService internally).
package internal

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jfrog/jfrog-client-go/auth"
	"github.com/jfrog/jfrog-client-go/http/jfroghttpclient"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayServices "github.com/jfrog/jfrog-client-go/xray/services"
)

// ---------------------------------------------------------------------------
// Request body types (Phase 0 stubs, kept here for Phase 3 parity)
// ---------------------------------------------------------------------------

// violationsRequest is the body sent to POST /api/v1/violations.
type violationsRequest struct {
	Filters    violationsFilters    `json:"filters"`
	Pagination violationsPagination `json:"pagination"`
}

type violationsFilters struct {
	WatchName      string              `json:"watch_name,omitempty"`
	ViolationType  string              `json:"violation_type"`
	Resources      violationsResources `json:"resources"`
	IncludeDetails bool                `json:"include_details"`
}

type violationsPagination struct {
	OrderBy string `json:"order_by"`
	Limit   int    `json:"limit"`
	Offset  int    `json:"offset"`
}

type violationsResources struct {
	Artifacts []violationsArtifact `json:"artifacts"`
}

type violationsArtifact struct {
	Repo string `json:"repo"`
	Path string `json:"path"`
}

// ---------------------------------------------------------------------------
// Violation types — canonical home after xray_cli.go deletion (Phase 5).
// These are used by both GetViolations (XrayService) and the test suite.
// ---------------------------------------------------------------------------

// xrayViolation represents the JSON structure from Xray Violations API.
// Each violation corresponds to a single security issue (CVE, malicious package, license, etc.).
// The MaliciousPackage field is extracted during the initial query so no separate Events API
// calls are needed downstream.
type xrayViolation struct {
	ViolationID        string          `json:"violation_id"`
	Description        string          `json:"description"`
	Severity           string          `json:"severity"`
	Type               string          `json:"type"`
	IssueID            string          `json:"issue_id"`
	InfectedComponents []string        `json:"infected_components"`
	InfectedVersions   []string        `json:"infected_versions"`
	FixVersions        []string        `json:"fix_versions,omitempty"`
	Created            string          `json:"created"`
	MaliciousPackage   bool            `json:"malicious_package,omitempty"`
	Properties         any             `json:"properties,omitempty"`
	ExtendedInformation *xrayViolationInfo `json:"extended_information,omitempty"`
}

type xrayViolationInfo struct {
	ShortDescription      string `json:"short_description"`
	FullDescription       string `json:"full_description"`
	JFrogResearchSeverity string `json:"jfrog_research_severity,omitempty"`
}

// extractCwesFromProperties extracts CWE IDs from violation properties.
func extractCwesFromProperties(props map[string]any) []string {
	var cwes []string
	if cweRaw, ok := props["cwe"]; ok {
		switch v := cweRaw.(type) {
		case []any:
			for _, c := range v {
				if s, ok := c.(string); ok {
					cwes = append(cwes, s)
				}
			}
		case string:
			cwes = append(cwes, v)
		}
	}
	return cwes
}

// SeverityCounts aggregates vulnerability counts from the Xray v2 summary API.
type SeverityCounts struct {
	Total    int
	Critical int
	High     int
	Medium   int
	Low      int
}

// SummaryIssue is a single deduplicated finding from the Xray v2 summary API.
type SummaryIssue struct {
	IssueID       string   // Xray issue identifier (e.g. XRAY-12345)
	Severity      string   // Standard severity: Critical, High, Medium, Low
	JFrogSeverity string   // JFrog Research severity (may differ from standard); empty if not provided
	Fixable       bool     // True if at least one affected component has a known fix version
	Platforms     []string // Platform labels where this issue was found (e.g. ["linux/amd64", "linux/arm64"])
}

// GetSummaryV2 queries POST /api/v2/summary/artifact with a list of artifact paths
// (each prefixed with the project key, e.g. "default/docker-local/img/tag/manifest.json").
// labels is a parallel slice of platform labels (e.g. "linux/amd64") for each path — used to
// populate SummaryIssue.Platforms so callers know which platforms each finding was detected on.
// labels may be nil or shorter than paths; missing entries are treated as no-label.
// Returns deduplicated severity counts and per-issue detail from Xray's indexed scan data
// without triggering an on-demand scan.
func (xs *XrayService) GetSummaryV2(paths, labels []string) (SeverityCounts, []SummaryIssue, error) {
	if xs == nil || xs.XrayDetails == nil {
		return SeverityCounts{}, nil, fmt.Errorf("XrayService not initialized")
	}
	if len(paths) == 0 {
		return SeverityCounts{}, nil, nil
	}

	type summaryReq struct {
		Paths []string `json:"paths"`
	}
	body, err := json.Marshal(summaryReq{Paths: paths})
	if err != nil {
		return SeverityCounts{}, nil, fmt.Errorf("failed to marshal v2 summary request: %w", err)
	}

	baseURL := strings.TrimRight(xs.XrayDetails.GetUrl(), "/")
	url := fmt.Sprintf("%s/api/v2/summary/artifact", baseURL)

	httpDetails := xs.XrayDetails.CreateHttpClientDetails()
	httpDetails.SetContentTypeApplicationJson()

	resp, respBody, err := xs.client.SendPost(url, body, &httpDetails)
	if err != nil {
		return SeverityCounts{}, nil, fmt.Errorf("POST /api/v2/summary/artifact failed: %w", err)
	}
	if resp.StatusCode != 200 {
		return SeverityCounts{}, nil, fmt.Errorf("v2 summary API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	type v2ExtendedInfo struct {
		JFrogResearchSeverity string `json:"jfrog_research_severity"`
	}
	type v2Component struct {
		FixedVersions []string `json:"fixed_versions"`
	}
	type v2Issue struct {
		IssueID             string          `json:"issue_id"`
		Severity            string          `json:"severity"`
		ExtendedInformation *v2ExtendedInfo `json:"extended_information"`
		Components          []v2Component   `json:"components"`
	}
	type v2Artifact struct {
		Issues []v2Issue `json:"issues"`
	}
	type v2Resp struct {
		Artifacts []v2Artifact `json:"artifacts"`
	}

	var parsed v2Resp
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return SeverityCounts{}, nil, fmt.Errorf("failed to parse v2 summary response: %w", err)
	}

	// Deduplicate by issue_id across all artifacts. For each issue, track which platform
	// labels it was found in (using the parallel labels slice).
	seen := make(map[string]*SummaryIssue)
	for artIdx, art := range parsed.Artifacts {
		label := ""
		if artIdx < len(labels) {
			label = labels[artIdx]
		}
		for _, issue := range art.Issues {
			if issue.IssueID == "" {
				continue
			}
			if existing, ok := seen[issue.IssueID]; ok {
				// Add platform label if not already recorded.
				if label != "" {
					found := false
					for _, p := range existing.Platforms {
						if p == label {
							found = true
							break
						}
					}
					if !found {
						existing.Platforms = append(existing.Platforms, label)
					}
				}
				// Merge fixable and JFrog severity from any artifact.
				if !existing.Fixable {
					for _, comp := range issue.Components {
						if len(comp.FixedVersions) > 0 {
							existing.Fixable = true
							break
						}
					}
				}
				if existing.JFrogSeverity == "" && issue.ExtendedInformation != nil {
					existing.JFrogSeverity = issue.ExtendedInformation.JFrogResearchSeverity
				}
				continue
			}
			si := &SummaryIssue{
				IssueID:  issue.IssueID,
				Severity: issue.Severity,
			}
			if issue.ExtendedInformation != nil {
				si.JFrogSeverity = issue.ExtendedInformation.JFrogResearchSeverity
			}
			for _, comp := range issue.Components {
				if len(comp.FixedVersions) > 0 {
					si.Fixable = true
					break
				}
			}
			if label != "" {
				si.Platforms = []string{label}
			}
			seen[issue.IssueID] = si
		}
	}

	var counts SeverityCounts
	issues := make([]SummaryIssue, 0, len(seen))
	for _, si := range seen {
		sort.Strings(si.Platforms)
		issues = append(issues, *si)
		switch si.Severity {
		case "Critical":
			counts.Critical++
		case "High":
			counts.High++
		case "Medium":
			counts.Medium++
		case "Low":
			counts.Low++
		}
	}
	counts.Total = len(seen)
	return counts, issues, nil
}

// violationWithMalicious wraps a xrayServices.Vulnerability with its malicious_package flag.
// The Violations API returns malicious_package on each violation so no separate Events API
// calls are needed — eliminating N+1 HTTP requests.
type violationWithMalicious struct {
	Vulnerability    xrayServices.Vulnerability
	MaliciousPackage bool
}

// ---------------------------------------------------------------------------
// XrayService — thin wrapper around an authenticated Xray HTTP client.
// Mirrors jfrog-client-go/xray/services/xsc/xsc.go:XscInnerService.
// ---------------------------------------------------------------------------

// XrayService wraps an authenticated *jfroghttpclient.JfrogHttpClient and
// provides typed methods for interacting with the Xray API. It is constructed
// from an existing XrayServicesManager's Client() and ServiceDetails, ensuring
// JWT tokens are properly initialized (Phase 1) and retries/backoff are inherited
// from the SDK client (no silent bypass).
type XrayService struct {
	client      *jfroghttpclient.JfrogHttpClient
	XrayDetails auth.ServiceDetails
}

// NewXrayService creates an XrayService from an authenticated Xray HTTP client
// and service details. The client is expected to already carry JWT bearer tokens
// generated by CreateInitialRefreshableTokensIfNeeded (Phase 1).
func NewXrayService(client *jfroghttpclient.JfrogHttpClient, details auth.ServiceDetails) *XrayService {
	return &XrayService{
		client:      client,
		XrayDetails: details,
	}
}

// ---------------------------------------------------------------------------
// GetViolations — synchronous read of POST /api/v1/violations
// ---------------------------------------------------------------------------

// GetViolations queries Xray for current violations on an artifact, returning
// vulnerability data alongside malicious_package status from the same response.
// This is the synchronous read of POST /api/v1/violations — no async report job.
//
// watchName filters results to a specific Xray watch; pass empty string to return all
// violations for the artifact across all watches (unscoped/unfiltered view).
// repo and path identify the artifact within Artifactory storage.
// projectKey scopes the query to a specific JFrog project (use "default" for the default project).
func (xs *XrayService) GetViolations(watchName, repo, path, projectKey string) ([]violationWithMalicious, error) {
	if xs == nil || xs.XrayDetails == nil {
		return nil, fmt.Errorf("XrayService not initialized")
	}
	if repo == "" || path == "" {
		return nil, fmt.Errorf("repo and path are required")
	}

	// The API expects path without the repo prefix (e.g. "jmhxraytest/15/manifest.json", not "docker-local/jmhxraytest/15/manifest.json").
	// Strip the repo prefix if callers passed a full artifact path.
	if strings.HasPrefix(path, repo+"/") {
		path = path[len(repo)+1:]
	}

	baseURL := strings.TrimRight(xs.XrayDetails.GetUrl(), "/")
	// Only scope to a specific project when explicitly requested; omitting the parameter
	// (or passing "default") keeps the query in the global/unscoped context, which is what
	// most single-project JFrog Platform setups require.
	apiURL := fmt.Sprintf("%s/api/v1/violations", baseURL)
	if projectKey != "" && projectKey != "default" {
		apiURL = fmt.Sprintf("%s?projectKey=%s", apiURL, projectKey)
	}

	httpDetails := xs.XrayDetails.CreateHttpClientDetails()
	httpDetails.SetContentTypeApplicationJson()

	type violationResponse struct {
		TotalViolations int             `json:"total_violations"`
		Violations      []xrayViolation `json:"violations"`
	}

	// The API paginates results (default page size is 25). Fetch all pages using
	// offset-based pagination so no violations are silently dropped.
	const pageSize = 100
	var allViolations []xrayViolation
	offset := 1

	for {
		req := violationsRequest{
			Filters: violationsFilters{
				WatchName:      watchName,
				ViolationType:  "Security",
				Resources:      violationsResources{Artifacts: []violationsArtifact{{Repo: repo, Path: path}}},
				IncludeDetails: true,
			},
			Pagination: violationsPagination{
				OrderBy: "severity",
				Limit:   pageSize,
				Offset:  offset,
			},
		}
		body, err := json.Marshal(req)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal violations request: %w", err)
		}

		log.Info(fmt.Sprintf("[XrayService] POST /api/v1/violations url=%s repo=%s path=%s watch=%s offset=%d",
			apiURL, repo, path, watchName, offset))

		resp, respBody, err := xs.client.SendPost(apiURL, body, &httpDetails)
		if err != nil {
			return nil, fmt.Errorf("POST /api/v1/violations failed: %w", err)
		}

		log.Info(fmt.Sprintf("[XrayService] resp status=%d body_len=%d", resp.StatusCode, len(respBody)))

		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("Xray returned status %d: %s", resp.StatusCode, string(respBody))
		}

		var parsed violationResponse
		if err := json.Unmarshal(respBody, &parsed); err != nil {
			return nil, fmt.Errorf("failed to parse violations response: %w", err)
		}

		allViolations = append(allViolations, parsed.Violations...)

		if len(allViolations) >= parsed.TotalViolations || len(parsed.Violations) < pageSize {
			break
		}
		offset += pageSize
	}

	var results []violationWithMalicious
	for _, v := range allViolations {
		vuln := xrayServices.Vulnerability{
			IssueId:    v.IssueID,
			Summary:    v.Description,
			Severity:   v.Severity,
			Technology: v.Type,
		}

		if v.Properties != nil {
			if propsMap, ok := v.Properties.(map[string]interface{}); ok {
				cwes := extractCwesFromProperties(propsMap)
				switch cve := propsMap["cve"].(type) {
				case string:
					if cve != "" {
						vuln.Cves = []xrayServices.Cve{{Id: cve, Cwe: cwes}}
					}
				case []interface{}:
					for _, c := range cve {
						if s, ok := c.(string); ok && s != "" {
							vuln.Cves = append(vuln.Cves, xrayServices.Cve{Id: s, Cwe: cwes})
						}
					}
				}
			}
		}

		if v.ExtendedInformation != nil {
			vuln.ExtendedInformation = &xrayServices.ExtendedInformation{
				FullDescription: v.ExtendedInformation.FullDescription,
			}
		}

		results = append(results, violationWithMalicious{
			Vulnerability:    vuln,
			MaliciousPackage: v.MaliciousPackage,
		})
	}
	return results, nil
}

// ---------------------------------------------------------------------------
// ArtifactoryService — thin wrapper around an authenticated Artifactory HTTP client.
// Mirrors the XrayService pattern: JfrogHttpClient + ServiceDetails, different base URL.
// ---------------------------------------------------------------------------

// ArtifactoryService wraps an authenticated *jfroghttpclient.JfrogHttpClient and
// provides typed methods for Artifactory REST API calls (AQL search, artifact fetch).
type ArtifactoryService struct {
	client     *jfroghttpclient.JfrogHttpClient
	artDetails auth.ServiceDetails
}

// NewArtifactoryService creates an ArtifactoryService from an authenticated Artifactory HTTP client
// and service details.
func NewArtifactoryService(client *jfroghttpclient.JfrogHttpClient, details auth.ServiceDetails) *ArtifactoryService {
	return &ArtifactoryService{client: client, artDetails: details}
}

// ArtifactoryURL returns the base Artifactory URL with any trailing slash stripped.
// Used by Exec() to derive the UI manifest link when services are injected for testing.
func (as *ArtifactoryService) ArtifactoryURL() string {
	return strings.TrimRight(as.artDetails.GetUrl(), "/")
}

// AQL response types — used by SearchArtifacts only.
type aqlResult struct {
	Results []aqlItem `json:"results"`
}

type aqlItem struct {
	Repo       string    `json:"repo"`
	Path       string    `json:"path"`
	Name       string    `json:"name"`
	SHA256     string    `json:"sha256"`
	Properties []aqlProp `json:"properties"`
}

type aqlProp struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// SearchArtifacts searches Artifactory for artifacts matching the given pattern using AQL.
// Pattern format: "repo/path/to/items/*" — mirrors the former jf rt search pattern format.
// Returns []rtArtifact in the same structure that docker_paths.go expects.
func (as *ArtifactoryService) SearchArtifacts(pattern string) ([]rtArtifact, error) {
	parts := strings.SplitN(pattern, "/", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid search pattern (expected repo/path/*): %s", pattern)
	}
	repo := parts[0]
	// Trim trailing "/*" to get the base directory path for AQL matching.
	pathBase := strings.TrimSuffix(parts[1], "/*")

	// AQL: find items directly in pathBase and one level deep (sha256__<digest>/manifest.json).
	aqlQuery := fmt.Sprintf(
		`items.find({"repo":"%s","$or":[{"path":"%s"},{"path":{"$match":"%s/*"}}]}).include("name","repo","path","sha256","property")`,
		repo, pathBase, pathBase,
	)

	baseURL := strings.TrimRight(as.artDetails.GetUrl(), "/")
	url := fmt.Sprintf("%s/api/search/aql", baseURL)

	log.Debug(fmt.Sprintf("[ArtifactoryService] AQL url=%s query=%s", url, aqlQuery))

	httpDetails := as.artDetails.CreateHttpClientDetails()
	// AQL endpoint expects text/plain content type (not application/json).
	if httpDetails.Headers == nil {
		httpDetails.Headers = make(map[string]string)
	}
	httpDetails.Headers["Content-Type"] = "text/plain"

	resp, respBody, err := as.client.SendPost(url, []byte(aqlQuery), &httpDetails)
	if err != nil {
		return nil, fmt.Errorf("AQL search failed: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("AQL search returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var result aqlResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse AQL response: %w", err)
	}

	artifacts := make([]rtArtifact, 0, len(result.Results))
	for _, item := range result.Results {
		props := make(map[string][]string)
		for _, p := range item.Properties {
			props[p.Key] = append(props[p.Key], p.Value)
		}
		// Reconstruct the full path (repo/path/name) to match the format rtArtifact expects.
		artifacts = append(artifacts, rtArtifact{
			Path:   item.Repo + "/" + item.Path + "/" + item.Name,
			SHA256: item.SHA256,
			Props:  props,
		})
	}
	return artifacts, nil
}

// FetchArtifactBody fetches the raw content of an artifact from Artifactory storage.
// repoKey is the repository name; artifactPath is the path within the repo (no repo prefix).
func (as *ArtifactoryService) FetchArtifactBody(repoKey, artifactPath string) ([]byte, error) {
	if repoKey == "" || artifactPath == "" {
		return nil, fmt.Errorf("repoKey and artifactPath are required")
	}

	baseURL := strings.TrimRight(as.artDetails.GetUrl(), "/")
	url := fmt.Sprintf("%s/%s/%s", baseURL, repoKey, artifactPath)

	log.Debug(fmt.Sprintf("[ArtifactoryService] FetchArtifactBody url=%s", url))

	httpDetails := as.artDetails.CreateHttpClientDetails()
	resp, body, _, err := as.client.SendGet(url, false, &httpDetails)
	if err != nil {
		return nil, fmt.Errorf("GET artifact failed: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Artifactory returned status %d for %s", resp.StatusCode, url)
	}
	return body, nil
}

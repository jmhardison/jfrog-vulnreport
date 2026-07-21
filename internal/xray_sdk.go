// Package internal — Xray SDK helpers (Phase 3 of the migration plan).
//
// This file replaces the `jf xr curl` subprocess wrappers from xray_cli.go with direct calls
// through the JFrog Xray SDK's HTTP client. The structure mirrors jfrog-client-go's
// XscInnerService (xray/services/xsc/xsc.go) — a thin wrapper around an authenticated
// *jfroghttpclient.JfrogHttpClient that exposes typed methods for Xray APIs.
//
// CRITICAL: There is NO typed SDK method for synchronous reads of /api/v1/violations.
// Confirmed by grep across jfrog-client-go@v1.55.0 — no ViolationsService, no GetViolations.
// ReportService.Violations() creates an ASYNC report job and is not what we need.
// The XrayService.GetViolations() method uses mgr.Client().SendPost() directly against
// /api/v1/violations, which is the only realistic path (mirrors XscInnerService internally).
package internal

import (
	"encoding/json"
	"fmt"
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
	Filters violationsFilters `json:"filters"`
}

type violationsFilters struct {
	WatchName     string              `json:"watch_name"`
	ViolationType string              `json:"violation_type"`
	Resources     violationsResources `json:"resources"`
	IncludeDetails bool               `json:"include_details"`
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
// watchName filters results to those relevant to a specific Xray watch (required;
// without it the API returns all violations in the project, potentially thousands).
// repo and path identify the artifact within Artifactory storage.
func (xs *XrayService) GetViolations(watchName, repo, path string) ([]violationWithMalicious, error) {
	if xs == nil || xs.XrayDetails == nil {
		return nil, fmt.Errorf("XrayService not initialized")
	}
	if watchName == "" || repo == "" || path == "" {
		return nil, fmt.Errorf("watchName, repo, and path are all required")
	}

	// The API expects path without the repo prefix (e.g. "jmhxraytest/15/manifest.json", not "docker-local/jmhxraytest/15/manifest.json").
	// Strip the repo prefix if callers passed a full artifact path.
	if strings.HasPrefix(path, repo+"/") {
		path = path[len(repo)+1:]
	}

	req := violationsRequest{
		Filters: violationsFilters{
			WatchName:     watchName,
			ViolationType: "Security",
			Resources: violationsResources{
				Artifacts: []violationsArtifact{{Repo: repo, Path: path}},
			},
			IncludeDetails: true,
		},
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal violations request: %w", err)
	}

	log.Info(fmt.Sprintf("[XrayService] GET /api/v1/violations url=%s repo=%s path=%s watch=%s body=%s",
		xs.XrayDetails.GetUrl(), repo, path, watchName, string(body)))

	httpDetails := xs.XrayDetails.CreateHttpClientDetails()
	httpDetails.SetContentTypeApplicationJson()
	url := fmt.Sprintf("%s/api/v1/violations", xs.XrayDetails.GetUrl())

	resp, respBody, err := xs.client.SendPost(url, body, &httpDetails)
	if err != nil {
		return nil, fmt.Errorf("POST /api/v1/violations failed: %w", err)
	}

	log.Info(fmt.Sprintf("[XrayService] resp status=%d body_len=%d body=%s", resp.StatusCode, len(respBody), string(respBody)))

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Xray returned status %d: %s", resp.StatusCode, string(respBody))
	}

	type violationResponse struct {
		TotalViolations int               `json:"total_violations"`
		Violations      []xrayViolation   `json:"violations"`
	}
	var parsed violationResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse violations response: %w", err)
	}

	var results []violationWithMalicious
	for _, v := range parsed.Violations {
		vuln := xrayServices.Vulnerability{
			IssueId:    v.IssueID,
			Summary:    v.Description,
			Severity:   v.Severity,
			Technology: v.Type, // Store type in Technology field for downstream classification
		}

		if v.Properties != nil {
			if propsMap, ok := v.Properties.(map[string]interface{}); ok {
				if cveId, ok := propsMap["cve"].(string); ok && cveId != "" {
					vuln.Cves = []xrayServices.Cve{
						{Id: cveId, Cwe: extractCwesFromProperties(propsMap)},
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

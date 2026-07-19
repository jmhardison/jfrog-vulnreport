// Package internal implements JFrog CLI subprocess wrappers for Xray and Artifactory APIs.
//
// All API calls go through `jf xr curl` / `jf rt search` subprocess commands because the plugin's
// JWT authentication token has audience restrictions that prevent direct SDK client usage (401 errors).
package internal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayServices "github.com/jfrog/jfrog-client-go/xray/services"
)

// runJFCmd executes a JFrog CLI command with the given arguments and returns stdout as bytes.
// Handles server-id flag injection and common error formatting for all CLI wrappers.
//
// All Xray API calls must go through this wrapper (or its typed siblings) because direct SDK
// client calls fail with 401 due to JWT audience restrictions on the plugin's authentication token.
func runJFCmd(serverId string, baseArgs []string) ([]byte, error) {
	args := append([]string{}, baseArgs...)
	if serverId != "" {
		args = append(args, "--server-id", serverId)
	}

	log.Debug(fmt.Sprintf("Running: jf %s", strings.Join(args, " ")))

	cmd := exec.Command("jf", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("jf command failed: %w", err)
	}

	return output, nil
}

// xraySummaryResult represents the JSON output from Xray SummaryService API
type xraySummaryResult struct {
	Artifacts []xrayArtifact `json:"artifacts"`
}

type xrayArtifact struct {
	Path string `json:"path"`
	Issues []xrayIssue `json:"issues"`
}

type xrayIssue struct {
	IssueId     string  `json:"issue_id"`
	Summary     string  `json:"summary"`
	Severity    string  `json:"severity"`
	IssueType   string  `json:"issue_type"`
	Description string  `json:"description"`
	Cves        []xrayCve `json:"cves"`
}

type xrayCve struct {
	Id          string   `json:"id"`
	CvssV2Score string   `json:"cvss_v2_score"`
	CvssV3Score string   `json:"cvss_v3_score"`
	Cwe         []string `json:"cwe"`
}

// summaryRequest is the payload for Xray SummaryService API
type summaryRequest struct {
	Paths     []string `json:"paths"`
	Checksums []string `json:"checksums,omitempty"`
}

// queryXrayViaCLI queries Xray using the JFrog CLI's xr curl wrapper, bypassing JWT audience restrictions.
func queryXrayViaCLI(serverId string, paths []string, checksums []string) (*xraySummaryResult, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("no paths provided")
	}

	log.Info(fmt.Sprintf("Querying Xray via CLI for %d path(s)...", len(paths)))

	req := summaryRequest{
		Paths:     paths,
		Checksums: checksums,
	}

	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	args := []string{"xr", "curl", "-XPOST", "/api/v1/summary/artifact", "-H", "Content-Type: application/json", "-d", string(bodyBytes)}
	output, err := runJFCmd(serverId, args)
	if err != nil {
		return nil, fmt.Errorf("jf xr curl failed: %w", err)
	}

	var result xraySummaryResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse jf xr curl output: %w", err)
	}

	log.Info(fmt.Sprintf("Found %d artifacts via JFrog CLI", len(result.Artifacts)))
	return &result, nil
}


// queryXraySearchViaCLI queries Xray artifact search API using CLI.
func queryXraySearchViaCLI(serverId string, query string) ([]byte, error) {
	if query == "" {
		return nil, fmt.Errorf("no query provided")
	}

	log.Debug(fmt.Sprintf("Querying Xray search via CLI for: %s", query))

	req := map[string]interface{}{
		"query":     query,
		"mandatory": true,
	}

	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	args := []string{"xr", "curl", "-XPOST", "/api/v1/artifact/search", "-H", "Content-Type: application/json", "-d", string(bodyBytes)}
	output, err := runJFCmd(serverId, args)
	if err != nil {
		return nil, fmt.Errorf("jf xr curl search failed: %w", err)
	}

	return output, nil
}

// queryArtifactorySearchViaCLI queries Artifactory's REST API to find Docker manifests/blobs.
// Returns JSON array of artifacts with path, sha256, and properties.
func queryArtifactorySearchViaCLI(serverId string, pattern string) ([]byte, error) {
	if pattern == "" {
		return nil, fmt.Errorf("no pattern provided")
	}

	log.Debug(fmt.Sprintf("Querying Artifactory search via CLI for: %s", pattern))

	args := []string{"rt", "search", pattern}
	output, err := runJFCmd(serverId, args)
	if err != nil {
		return nil, fmt.Errorf("jf rt search failed: %w", err)
	}

	return output, nil
}

// fetchArtifactBodyViaCLI fetches the raw body of an artifact stored in Xray using CLI.
// Used to read manifest.json or list.manifest.json content for digest extraction.
func fetchArtifactBodyViaCLI(serverId string, artifactPath string) ([]byte, error) {
	if artifactPath == "" {
		return nil, fmt.Errorf("no artifact path provided")
	}

	log.Debug(fmt.Sprintf("Fetching artifact body via CLI for: %s", artifactPath))

	args := []string{"xr", "curl", "-XGET", fmt.Sprintf("/api/v1/artifact/get?path=%s", artifactPath)}
	output, err := runJFCmd(serverId, args)
	if err != nil {
		return nil, fmt.Errorf("jf xr curl fetch failed: %w", err)
	}

	return output, nil
}

// fetchArtifactoryArtifactBody fetches the raw body of an artifact stored in Artifactory using the JFrog SDK's
// HTTP client. Unlike Xray's artifact-get endpoint (which serves scan results), this retrieves actual file content
// from Artifactory storage — required for list.manifest.json which holds per-platform digest metadata.
func fetchArtifactoryArtifactBody(serverDetails *config.ServerDetails, repoKey, artifactPath string) ([]byte, error) {
	if serverDetails == nil || repoKey == "" || artifactPath == "" {
		return nil, fmt.Errorf("server details, repo key, and artifact path are all required")
	}

	// Note: serverDetails.GetArtifactoryUrl() already includes the /artifactory prefix (e.g., "https://host/jfrog/artifactory"),
	// so we do NOT add another /artifactory/ — doing so produces a 404 from double-prefixing.
	baseURL := strings.TrimRight(serverDetails.GetArtifactoryUrl(), "/")
	url := fmt.Sprintf("%s/%s/%s", baseURL, repoKey, artifactPath)

	log.Debug(fmt.Sprintf("Fetching Artifactory artifact body: %s", url))

	// Use the JFrog SDK's HTTP client (configured with proper auth from server details).
	client, err := getHTTPClient(serverDetails)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Artifactory returned status %d for %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	log.Debug(fmt.Sprintf("Fetched %d bytes from Artifactory", len(body)))
	return body, nil
}

// getHTTPClient constructs an authenticated HTTP client using credentials from JFrog server details.
// Handles access token (Bearer), username/password, and anonymous authentication automatically.
func getHTTPClient(serverDetails *config.ServerDetails) (*http.Client, error) {
	var transport http.RoundTripper = &http.Transport{}

	artifactoryURL := strings.TrimRight(serverDetails.GetArtifactoryUrl(), "/")
	user := serverDetails.GetUser()
	password := serverDetails.GetPassword()
	accessToken := serverDetails.GetAccessToken()

	if accessToken != "" {
		// Access token auth: Bearer <token>
		transport = &bearerTransport{
			base:    transport,
			token:   accessToken,
			baseURL: artifactoryURL,
		}
	} else if user != "" && password != "" {
		// Username/password auth: Basic <base64(user:password)>
		creds := base64Encode([]byte(user + ":" + password))
		transport = &basicTransport{
			base:     transport,
			creds:    creds,
			baseURL:  artifactoryURL,
		}
	}

	return &http.Client{Transport: transport}, nil
}

// bearerTransport adds Bearer token auth headers to requests against the configured base URL.
type bearerTransport struct {
	base    http.RoundTripper
	token   string
	baseURL string
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !strings.HasPrefix(req.URL.String(), t.baseURL) {
		return t.base.RoundTrip(req) // Pass through non-matching URLs unchanged
	}
	req = cloneRequest(req)
	req.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(req)
}

// basicTransport adds Basic auth headers to requests against the configured base URL.
type basicTransport struct {
	base     http.RoundTripper
	creds    string
	baseURL  string
}

func (t *basicTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !strings.HasPrefix(req.URL.String(), t.baseURL) {
		return t.base.RoundTrip(req)
	}
	req = cloneRequest(req)
	req.Header.Set("Authorization", "Basic "+t.creds)
	return t.base.RoundTrip(req)
}

// cloneRequest creates a shallow copy of the request with cloned headers.
func cloneRequest(req *http.Request) *http.Request {
	reqCopy := new(http.Request)
	*reqCopy = *req
	reqCopy.Header = make(http.Header, len(req.Header))
	for k, vals := range req.Header {
		for _, v := range vals {
			reqCopy.Header.Add(k, v)
		}
	}
	return reqCopy
}

// base64Encode encodes bytes to a URL-safe base64 string (no padding).
func base64Encode(data []byte) string {
	encoded := make([]byte, base64EncodedLen(len(data)))
	base64.StdEncoding.Encode(encoded, data)
	return strings.TrimRight(string(encoded), "=") // Strip trailing = for JFrog compat
}

// base64EncodedLen returns the length of a base64-encoded string for the given input length.
func base64EncodedLen(n int) int {
	return ((n + 2) / 3) * 4
}

// queryXrayViolationsViaCLI queries the Xray Violations API for an artifact.
// This is the correct endpoint for Docker image vulnerability queries (not SummaryService).
func queryXrayViolationsViaCLI(serverId string, projectKey string, artifactPath string) ([]byte, error) {
	if artifactPath == "" {
		return nil, fmt.Errorf("no artifact path provided")
	}

	log.Debug(fmt.Sprintf("Querying Xray Violations API for: %s (project: %s)", artifactPath, projectKey))

	req := map[string]interface{}{
		"filters": map[string]interface{}{
			"resources": map[string]interface{}{
				"artifacts": []map[string]string{
					{"repo": extractRepoFromPath(artifactPath), "path": stripRepoPrefix(artifactPath)},
				},
			},
			"include_details": true,
		},
	}

	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal violations request: %w", err)
	}

	args := []string{"xr", "curl", "-XPOST", fmt.Sprintf("/api/v1/violations?projectKey=%s", projectKey), "-H", "Content-Type: application/json", "-d", string(bodyBytes)}
	output, err := runJFCmd(serverId, args)
	if err != nil {
		return nil, fmt.Errorf("jf xr curl violations failed: %w", err)
	}

	return output, nil
}

// extractRepoFromPath extracts the repository key from an artifact path.
// For example: "docker-local/jmhxraytest/10/manifest.json" → "docker-local"
func extractRepoFromPath(path string) string {
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 2 {
		return parts[0] // First segment is the repo
	}
	return "" // No slash means no repo prefix (shouldn't happen for Docker paths)
}

// stripRepoPrefix removes the repository key prefix from an artifact path.
// For example: "docker-local/jmhxraytest/10/manifest.json" → "jmhxraytest/10/manifest.json"
func stripRepoPrefix(path string) string {
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 2 {
		return parts[1] // Return everything after the first slash (repo prefix)
	}
	return path // No slash means no repo to strip
}

// xrayViolation represents the JSON structure from Xray Violations API.
// Each violation corresponds to a single security issue (CVE, malicious package, license violation, etc.)
// found in the scanned artifact. The MaliciousPackage field is extracted during initial query and passed
// through to downstream code — no separate Events API calls are needed.
type xrayViolation struct {
	ViolationID          string      `json:"violation_id"`
	Description          string      `json:"description"`
	Severity             string      `json:"severity"` // Low, Medium, High, Critical (or "Malicious" for malicious packages)
	Type                 string      `json:"type"`     // Issue type: CVE, Malware, License, etc.
	IssueID              string      `json:"issue_id"` // Xray issue ID (e.g., "XRAY-12345")
	InfectedComponents   []string    `json:"infected_components"`
	InfectedVersions     []string    `json:"infected_versions"`
	FixVersions          []string    `json:"fix_versions,omitempty"`
	Created              string      `json:"created"`
	MaliciousPackage     bool        `json:"malicious_package,omitempty"` // Key field — used for malicious detection without Events API calls
	Properties           any       `json:"properties,omitempty"` // CVE data and other metadata stored as flat key-value pairs
	ExtendedInformation  *xrayViolationInfo `json:"extended_information,omitempty"`
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
// The Violations API already returns malicious_package on each violation, so we extract it here
// instead of making separate Events API calls per issue ID (eliminating N+1 HTTP requests).
type violationWithMalicious struct {
	Vulnerability    xrayServices.Vulnerability
	MaliciousPackage bool
}

// queryXrayViolationsViaCLIVulnerabilitiesWithMalicious queries Xray Violations API and returns
// vulnerabilities alongside their malicious_package status from the same response.
//
// This is the primary entry point for Docker image vulnerability queries. It extracts both
// vulnerability data AND malicious_package status in a single HTTP request, eliminating the need
// for separate Events API calls per issue ID (which previously caused N+1 HTTP requests).
func queryXrayViolationsViaCLIVulnerabilitiesWithMalicious(serverId, projectKey, artifactPath string) ([]violationWithMalicious, error) {
	body, err := queryXrayViolationsViaCLI(serverId, projectKey, artifactPath)
	if err != nil {
		return nil, err
	}

	type violationResponse struct {
		TotalViolations int             `json:"total_violations"`
		Violations      []xrayViolation `json:"violations"`
	}

	var resp violationResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse violations response: %w", err)
	}

	log.Info(fmt.Sprintf("Found %d violations for artifact", resp.TotalViolations))

	var results []violationWithMalicious
	for _, v := range resp.Violations {
		vuln := xrayServices.Vulnerability{
			IssueId:    v.IssueID,
			Summary:    v.Description,
			Severity:   v.Severity,
			Technology: v.Type, // Store type in Technology field
		}

		// Extract CVE info from properties if present
		if v.Properties != nil {
			if propsMap, ok := v.Properties.(map[string]interface{}); ok {
				if cveId, ok := propsMap["cve"].(string); ok && cveId != "" {
					cve := xrayServices.Cve{
						Id:   cveId,
						Cwe:  extractCwesFromProperties(propsMap),
					}
					vuln.Cves = []xrayServices.Cve{cve}
				}
			}
		}

		// Preserve detailed information for rich reporting
		if v.ExtendedInformation != nil {
			vuln.ExtendedInformation = &xrayServices.ExtendedInformation{
				FullDescription: v.ExtendedInformation.FullDescription,
			}
		}

		results = append(results, violationWithMalicious{
			Vulnerability:  vuln,
			MaliciousPackage: v.MaliciousPackage,
		})
	}

	return results, nil
}
package internal

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

// runJFCmd executes a JFrog CLI command with the given arguments and returns stdout as bytes.
// Handles server-id flag injection and common error formatting for all CLI wrappers.
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
type xrayViolation struct {
	ViolationID          string      `json:"violation_id"`
	Description          string      `json:"description"`
	Severity             string      `json:"severity"`
	Type                 string      `json:"type"`
	IssueID              string      `json:"issue_id"`
	InfectedComponents   []string    `json:"infected_components"`
	InfectedVersions     []string    `json:"infected_versions"`
	FixVersions          []string    `json:"fix_versions,omitempty"`
	Created              string      `json:"created"`
	MaliciousPackage     bool        `json:"malicious_package,omitempty"`
	Properties           interface{} `json:"properties,omitempty"` // Changed to interface{} for flexibility
	ExtendedInformation  *xrayViolationInfo `json:"extended_information,omitempty"`
}

type xrayViolationInfo struct {
	ShortDescription  string `json:"short_description"`
	FullDescription   string `json:"full_description"`
	JFrogResearchSeverity string `json:"jfrog_research_severity,omitempty"`
}

// extractCwesFromProperties extracts CWE IDs from violation properties.
func extractCwesFromProperties(props map[string]interface{}) []string {
	var cwes []string
	if cweRaw, ok := props["cwe"]; ok {
		switch v := cweRaw.(type) {
		case []interface{}:
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

// violationWithMalicious wraps a services.Vulnerability with its malicious_package flag.
// The Violations API already returns malicious_package on each violation, so we extract it
// here instead of making separate Events API calls per issue ID (eliminating N+1 HTTP requests).
type violationWithMalicious struct {
	Vulnerability  services.Vulnerability
	MaliciousPackage bool
}

// queryXrayViolationsViaCLIVulnerabilitiesWithMalicious queries Xray Violations API and returns
// vulnerabilities alongside their malicious_package status from the same response.
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
		vuln := services.Vulnerability{
			IssueId:    v.IssueID,
			Summary:    v.Description,
			Severity:   v.Severity,
			Technology: v.Type, // Store type in Technology field
		}

		// Extract CVE info from properties if present
		if v.Properties != nil {
			if propsMap, ok := v.Properties.(map[string]interface{}); ok {
				if cveId, ok := propsMap["cve"].(string); ok && cveId != "" {
					cve := services.Cve{
						Id:   cveId,
						Cwe:  extractCwesFromProperties(propsMap),
					}
					vuln.Cves = []services.Cve{cve}
				}
			}
		}

		// Preserve detailed information for rich reporting
		if v.ExtendedInformation != nil {
			vuln.ExtendedInformation = &services.ExtendedInformation{
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
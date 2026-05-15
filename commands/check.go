// check will search for vulnerabilities in the specified image and generate a report based on existing scans
package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/artifactory"
	artifactoryAuth "github.com/jfrog/jfrog-client-go/artifactory/auth"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray"
	xrayAuth "github.com/jfrog/jfrog-client-go/xray/auth"
	"github.com/jfrog/jfrog-client-go/xray/services"
	clientconfig "github.com/jfrog/jfrog-client-go/config"
)

func GetCheckCommand() components.Command {
	return components.Command{
		Name:        "check",
		Description: "Checks existing vulnerability scans for a Docker image across platforms.",
		Aliases:     []string{"ck"},
		Arguments:   getCheckArguments(),
		Flags:       getCheckFlags(),
		EnvVars:     getCheckEnvVar(),
		Action: func(c *components.Context) error {
			return checkCmd(c)
		},
	}
}

func getCheckArguments() []components.Argument {
	return []components.Argument{
		{
			Name:        "image",
			Description: "The Docker image name and tag (e.g., myrepo/myimage:tag).",
		},
	}
}

func getCheckFlags() []components.Flag {
	return []components.Flag{
		components.NewStringFlag(
			"server-id",
			"JFrog server configuration ID to use.",
		),
		components.NewStringFlag(
			"platform",
			"Filter results by platform architecture (e.g., amd64, arm64).",
		),
		components.NewStringFlag(
			"os",
			"Filter results by operating system (e.g., linux, windows).",
		),
		components.NewBoolFlag(
			"fail-on-vuln",
			"Exit with error code if vulnerabilities are found.",
			components.WithBoolDefaultValue(false),
		),
		components.NewStringFlag(
			"output",
			"Output format: json (default), github-md (silent markdown for GitHub).",
		),
		components.NewStringFlag(
			"min-severity",
			"Minimum severity level to display in findings (Low, Medium, High, Critical, Malicious). Summary shows all severities.",
		),

		components.NewBoolFlag(
			"show-findings",
			"Display detailed security findings table (default: true).",
			components.WithBoolDefaultValue(true),
		),
		components.NewBoolFlag(
			"debug-paths",
			"Enable debug mode to explore repository structure.",
			components.WithBoolDefaultValue(false),
		),
		components.NewStringFlag(
			"docker-registry-url",
			"Docker registry URL (e.g., https://company-docker-local.jfrog.io). If not specified, will be constructed from JFROG_URL.",
		),
	}
}

func getCheckEnvVar() []components.EnvVar {
	return []components.EnvVar{}
}

// Docker manifest data structures
type DockerManifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        Descriptor   `json:"config"`
	Layers        []Descriptor `json:"layers"`
}

type ManifestList struct {
	SchemaVersion int                `json:"schemaVersion"`
	MediaType     string             `json:"mediaType"`
	Manifests     []PlatformManifest `json:"manifests"`
}

type PlatformManifest struct {
	Descriptor
	Platform Platform `json:"platform"`
}

type Platform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant,omitempty"`
}

type Descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// Constants for media types
const (
	MediaTypeManifest     = "application/vnd.docker.distribution.manifest.v2+json"
	MediaTypeManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
	MediaTypeOCIManifest  = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeOCIIndex     = "application/vnd.oci.image.index.v1+json"
)

type checkConfiguration struct {
	imageName         string
	serverId          string
	platform          string
	os                string
	failOnVuln        bool
	output            string
	silent            bool
	minSeverity       string
	showFindings      bool
	debugPaths        bool
	dockerRegistryURL string
}

type VulnerabilityReport struct {
	ImageName     string                       `json:"imageName"`
	Platforms     []PlatformVulnerabilityInfo  `json:"platforms"`
	TotalIssues   int                          `json:"totalIssues"`
	CriticalCount int                          `json:"criticalCount"`
	HighCount     int                          `json:"highCount"`
	MediumCount   int                          `json:"mediumCount"`
	LowCount      int                          `json:"lowCount"`
	GeneratedAt   string                       `json:"generatedAt"`
}

type PlatformVulnerabilityInfo struct {
	Platform        Platform                 `json:"platform"`
	ManifestDigest  string                   `json:"manifestDigest"`
	Vulnerabilities []services.Vulnerability `json:"vulnerabilities"`
	LayerCount      int                      `json:"layerCount"`
	TotalSize       int64                    `json:"totalSize"`
}

// Docker Registry API client
type DockerRegistryClient struct {
	BaseURL    string
	HTTPClient *http.Client
	Username   string
	Password   string
	Token      string
}

func checkCmd(c *components.Context) error {
	if len(c.Arguments) == 0 {
		return fmt.Errorf("image name is required. Usage: check <image:tag>")
	}
	if len(c.Arguments) > 1 {
		return fmt.Errorf("too many arguments. Expected: check <image:tag>")
	}

	output := c.GetStringFlagValue("output")
	if output == "" {
		output = "json"  // Default to JSON
	}

	conf := &checkConfiguration{
		imageName:         c.Arguments[0],
		serverId:          c.GetStringFlagValue("server-id"),
		platform:          c.GetStringFlagValue("platform"),
		os:                c.GetStringFlagValue("os"),
		failOnVuln:        c.GetBoolFlagValue("fail-on-vuln"),
		output:            output,
		silent:            output == "github-md",
		minSeverity:       c.GetStringFlagValue("min-severity"),
		showFindings:      c.GetBoolFlagValue("show-findings"),
		debugPaths:        c.GetBoolFlagValue("debug-paths"),
		dockerRegistryURL: c.GetStringFlagValue("docker-registry-url"),
	}

	// Configure log level based on output format
	if conf.silent {
		// In silent mode (github-md output), only show ERROR messages
		log.SetLogger(log.NewLogger(log.ERROR, os.Stderr))
	}

	// Parse image name to extract repository and tag
	repoKey, imageName, tag, err := parseImageName(conf.imageName)
	if err != nil {
		return fmt.Errorf("invalid image format: %w", err)
	}

	// Only log if not in silent mode
	if !conf.silent {
		log.Info(fmt.Sprintf("Checking vulnerabilities for image: %s/%s:%s", repoKey, imageName, tag))
	}

	// Setup JFrog service connections
	serverDetails, err := getServerDetails(conf.serverId)
	if err != nil {
		return fmt.Errorf("failed to get server configuration: %w", err)
	}

	rtManager, err := setupArtifactory(serverDetails)
	if err != nil {
		return fmt.Errorf("failed to setup Artifactory connection: %w", err)
	}

	xrManager, err := setupXray(serverDetails)
	if err != nil {
		return fmt.Errorf("failed to setup Xray connection: %w", err)
	}

	// If debug mode is enabled, explore repository structure first
	if conf.debugPaths {
		if err := exploreRepositoryStructure(rtManager, repoKey, imageName, tag); err != nil {
			log.Warn(fmt.Sprintf("Repository exploration failed: %v", err))
		}
	}

	// Create Docker Registry client for manifest retrieval
	dockerClient, err := createDockerRegistryClient(conf, serverDetails)
	if err != nil {
		return fmt.Errorf("failed to create Docker registry client: %w", err)
	}

	// Generate vulnerability report
	report, err := generateVulnerabilityReport(conf, rtManager, xrManager, dockerClient, repoKey, imageName, tag)
	if err != nil {
		return fmt.Errorf("failed to generate vulnerability report: %w", err)
	}

	// Output the report
	if err := outputReport(xrManager, report, conf.output, conf.minSeverity, conf.showFindings); err != nil {
		return fmt.Errorf("failed to output report: %w", err)
	}

	// Check if we should fail on vulnerabilities
	if conf.failOnVuln && report.TotalIssues > 0 {
		return fmt.Errorf("found %d vulnerability issues", report.TotalIssues)
	}

	return nil
}

// Helper functions for enhanced report formatting

// extractIssueType gets the issue type from JFrog's official classification
func extractIssueType(vuln services.Vulnerability) string {
	// Use JFrog's official issue type classification stored in Technology field
	if vuln.Technology != "" {
		// Capitalize first letter for display
		issueType := strings.Title(strings.ToLower(vuln.Technology))
		return issueType
	}
	
	// Fallback: classify based on issue ID pattern (for legacy compatibility)
	if strings.Contains(strings.ToLower(vuln.IssueId), "xray-") {
		return "Security"
	}
	if strings.Contains(strings.ToLower(vuln.IssueId), "license") {
		return "License"  
	}
	if strings.Contains(strings.ToLower(vuln.IssueId), "malware") {
		return "Malware"
	}
	if strings.Contains(strings.ToLower(vuln.IssueId), "secret") {
		return "Secret"
	}
	if len(vuln.Cves) > 0 {
		return "CVE"
	}
	return "Security" // Default
}

// checkMaliciousPackage queries the JFrog Events API to check if an issue is malicious
func checkMaliciousPackage(xrManager *xray.XrayServicesManager, issueId string) (bool, error) {
	if issueId == "" {
		return false, nil
	}
	
	// Build the Events API endpoint URL
	xrayDetails := xrManager.Config().GetServiceDetails()
	baseURL := strings.TrimSuffix(xrayDetails.GetUrl(), "/")
	eventsEndpoint := fmt.Sprintf("%s/xray/api/v2/events/%s", baseURL, issueId)
	
	log.Debug(fmt.Sprintf("Making Events API request for %s", issueId))
	
	// Create HTTP request
	httpClientDetails := xrayDetails.CreateHttpClientDetails()
	client := xrManager.Client()
	
	// Make GET request to Events API
	resp, body, _, err := client.SendGet(eventsEndpoint, true, &httpClientDetails)
	if err != nil {
		log.Debug(fmt.Sprintf("Failed to query Events API for %s: %v", issueId, err))
		return false, err
	}
	
	if resp.StatusCode == 404 {
		log.Debug(fmt.Sprintf("Issue %s not found in Events API (404) - not malicious", issueId))
		return false, nil
	}
	
	if resp.StatusCode != 200 {
		log.Debug(fmt.Sprintf("Events API returned status %d for %s", resp.StatusCode, issueId))
		return false, fmt.Errorf("events API returned status %d", resp.StatusCode)
	}
	
	log.Debug(fmt.Sprintf("Events API success (200) for %s", issueId))
	
	// First, log the raw response for debugging
	log.Info(fmt.Sprintf("🔍 Raw Events API response for %s: %s", issueId, string(body)))
	
	// Try to parse as generic JSON first to see all fields
	var genericResponse map[string]interface{}
	if err := json.Unmarshal(body, &genericResponse); err == nil {
		log.Info(fmt.Sprintf("📋 All fields in Events API response for %s:", issueId))
		for key, value := range genericResponse {
			log.Info(fmt.Sprintf("  %s: %v", key, value))
		}
	}
	
	// Parse response into our struct
	var eventsResponse EventsAPIResponse
	if err := json.Unmarshal(body, &eventsResponse); err != nil {
		log.Warn(fmt.Sprintf("Failed to parse Events API response for %s: %v", issueId, err))
		return false, err
	}
	
	log.Info(fmt.Sprintf("✅ Issue %s malicious_package field: %t", issueId, eventsResponse.MaliciousPackage))
	return eventsResponse.MaliciousPackage, nil
}

// isMaliciousWithCache checks if an issue is malicious using Events API with caching
var maliciousCache = make(map[string]bool)
var maliciousCacheMutex sync.RWMutex

func isMaliciousWithCache(xrManager *xray.XrayServicesManager, issueId string) bool {
	if issueId == "" {
		return false
	}
	
	// Check cache first
	maliciousCacheMutex.RLock()
	if cached, exists := maliciousCache[issueId]; exists {
		maliciousCacheMutex.RUnlock()
		return cached
	}
	maliciousCacheMutex.RUnlock()
	
	// Query Events API
	isMalicious, err := checkMaliciousPackage(xrManager, issueId)
	if err != nil {
		log.Debug(fmt.Sprintf("Events API error for %s: %v", issueId, err))
		return false
	}
	
	if isMalicious {
		log.Info(fmt.Sprintf("🚨 Events API confirmed malicious package: %s", issueId))
	}
	
	// Cache the result
	maliciousCacheMutex.Lock()
	maliciousCache[issueId] = isMalicious
	maliciousCacheMutex.Unlock()
	
	return isMalicious
}

// getSeverityIcon returns an appropriate icon for severity levels
func getSeverityIcon(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "⚪"
	}
}

// Helper function to get minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// CORRECTED artifact summary approach
// tryArtifactSummaryV2 uses the new v2 artifact summary API with enhanced component details
// 
// The v2 API endpoint (/api/v2/summary/artifact) provides significant improvements over v1:
// - Component-level vulnerability details within each issue
// - Information about which specific components are affected  
// - Fixed version recommendations for vulnerable components
// - Enhanced metadata about package types and versions
//
// This function makes a direct HTTP call to the v2 endpoint since the JFrog Client SDK
// (as of v1.55.0) does not yet expose v2 functionality. It reuses the same authentication 
// mechanism as the SDK to ensure consistency.
//
// Returns component details in the format:
//   Issue -> Components -> [ComponentID, Version, PkgType, FixedVersions]
//
// The v2 API requires Xray 3.x with v2 API support. This function gracefully falls back
// to v1 API if v2 is not available (404) or returns errors.
//
// Official API Specification:
//   https://docs.jfrog.com/security/reference/artifact-summary_artifacts-v2-openapi
func tryArtifactSummaryV2(xrManager *xray.XrayServicesManager, artifactPath, sha256 string) ([]services.Vulnerability, error) {
	log.Info(fmt.Sprintf("Trying ArtifactSummary v2 for path: %s", artifactPath))
	
	xrayDetails := xrManager.Config().GetServiceDetails()
	baseURL := strings.TrimSuffix(xrayDetails.GetUrl(), "/")
	v2Endpoint := baseURL + "/api/v2/summary/artifact"
	
	// Prepare v2 API request payload according to official spec
	// https://docs.jfrog.com/security/reference/artifact-summary_artifacts-v2-openapi
	requestPayload := map[string]interface{}{
		"paths": []string{artifactPath},
	}
	
	// Add checksums if provided
	// Note: According to spec, "If both are provided, checksums are ignored"
	// But we include both for completeness - Xray will use paths and ignore checksums
	if sha256 != "" {
		requestPayload["checksums"] = []string{sha256}
		log.Info(fmt.Sprintf("Including checksum: %s (will be ignored since paths provided)", sha256))
	}
	
	// Convert to JSON
	jsonData, err := json.Marshal(requestPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request payload: %v", err)
	}
	
	// Create HTTP request
	req, err := http.NewRequest("POST", v2Endpoint, strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %v", err)
	}
	
	// Set headers
	req.Header.Set("Content-Type", "application/json")
	
	// Add authentication headers using the same mechanism as the SDK
	authDetails := xrayDetails.CreateHttpClientDetails()
	for key, value := range authDetails.Headers {
		req.Header.Set(key, value)
		log.Debug(fmt.Sprintf("Setting header: %s = %s", key, value))
	}
	
	log.Info(fmt.Sprintf("Making ArtifactSummary v2 API call to: %s", v2Endpoint))
	log.Debug(fmt.Sprintf("Request payload: %s", string(jsonData)))
	
	// Log authentication method being used
	if authDetails.AccessToken != "" {
		log.Debug(fmt.Sprintf("Using Access Token authentication: %s", authDetails.AccessToken[:10]+"..."))
	} else if authDetails.ApiKey != "" {
		log.Debug(fmt.Sprintf("Using API Key authentication: %s", authDetails.ApiKey[:10]+"..."))
	} else if authDetails.User != "" && authDetails.Password != "" {
		log.Debug(fmt.Sprintf("Using Basic authentication: %s", authDetails.User))
	} else {
		log.Warn("No authentication credentials found")
	}
	
	// Make HTTP request with enhanced error handling
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Warn(fmt.Sprintf("ArtifactSummary v2 HTTP request failed: %v", err))
		// Check if this might be a connectivity or authentication issue
		if strings.Contains(err.Error(), "connection") {
			return nil, fmt.Errorf("connection error - check Xray URL and network connectivity: %v", err)
		} else if strings.Contains(err.Error(), "authentication") || strings.Contains(err.Error(), "401") {
			return nil, fmt.Errorf("authentication error - check access token/credentials: %v", err)
		}
		return nil, err
	}
	defer resp.Body.Close()
	
	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}
	
	// Enhanced HTTP error handling
	if resp.StatusCode != 200 {
		log.Warn(fmt.Sprintf("ArtifactSummary v2 API returned status %d: %s", resp.StatusCode, string(respBody)))
		
		switch resp.StatusCode {
		case 401:
			log.Warn("v2 API authentication failed - this may indicate v2 API is not available or requires different authentication")
			return nil, fmt.Errorf("v2 API authentication failed (401) - falling back to v1 API")
		case 403:
			return nil, fmt.Errorf("access forbidden (403) - user lacks Read permissions for Xray")
		case 404:
			return nil, fmt.Errorf("v2 API endpoint not found (404) - this Xray version may not support v2 API, falling back to v1")
		case 415:
			return nil, fmt.Errorf("failed to parse JSON request body (415) - check request format")
		case 500:
			return nil, fmt.Errorf("internal server error (500) - Xray service issue")
		default:
			return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(respBody))
		}
	}
	
	// Parse v2 response
	var v2Response ArtifactSummaryV2Response
	if err := json.Unmarshal(respBody, &v2Response); err != nil {
		return nil, fmt.Errorf("failed to parse v2 response: %v", err)
	}
	
	// Check for API errors in response
	if len(v2Response.Errors) > 0 {
		log.Warn("API returned errors:")
		for _, apiError := range v2Response.Errors {
			log.Warn(fmt.Sprintf("  Error for %s: %s", apiError.Identifier, apiError.Error))
		}
		return nil, fmt.Errorf("API returned %d errors", len(v2Response.Errors))
	}
	
	log.Info(fmt.Sprintf("ArtifactSummary v2 found %d artifacts", len(v2Response.Artifacts)))
	
	// Convert v2 response to existing Vulnerability format
	return convertV2ResponseToVulnerabilities(v2Response), nil
}

// tryArtifactSummary uses the legacy v1 API as fallback
func tryArtifactSummary(xrManager *xray.XrayServicesManager, artifactPath, sha256 string) ([]services.Vulnerability, error) {
	log.Info(fmt.Sprintf("Trying ArtifactSummary v1 (fallback) for path: %s", artifactPath))
	
	// CRITICAL FIX: Properly initialize the summary service
	summaryService := services.NewSummaryService(xrManager.Client())
	
	// CRITICAL: Must set XrayDetails on the service (this was missing!)
	xrayDetails := xrManager.Config().GetServiceDetails()
	summaryService.XrayDetails = xrayDetails
	
	params := services.ArtifactSummaryParams{
		Paths: []string{artifactPath},
	}
	
	if sha256 != "" {
		params.Checksums = []string{sha256}
		log.Info(fmt.Sprintf("Including checksum: %s", sha256))
	}
	
	log.Info(fmt.Sprintf("Making ArtifactSummary v1 API call to: %s", xrayDetails.GetUrl()))
	
	summary, err := summaryService.GetArtifactSummary(params)
	if err != nil {
		log.Warn(fmt.Sprintf("ArtifactSummary v1 failed: %v", err))
		return nil, err
	}

	// Check for API errors in response
	if len(summary.Errors) > 0 {
		log.Warn("API returned errors:")
		for _, apiError := range summary.Errors {
			log.Warn(fmt.Sprintf("  Error for %s: %s", apiError.Identifier, apiError.Error))
		}
		return nil, fmt.Errorf("API returned %d errors", len(summary.Errors))
	}

	log.Info(fmt.Sprintf("ArtifactSummary v1 found %d artifacts", len(summary.Artifacts)))
	
	var vulnerabilities []services.Vulnerability
	if summary != nil && len(summary.Artifacts) > 0 {
		for i, artifact := range summary.Artifacts {
			log.Info(fmt.Sprintf("Artifact %d: %s (Component: %s, Type: %s, Issues: %d)", 
				i+1, artifact.General.Path, artifact.General.ComponentId, 
				artifact.General.PkgType, len(artifact.Issues)))
			
			for _, issue := range artifact.Issues {

				
				vuln := services.Vulnerability{
					IssueId:    issue.IssueId,
					Summary:    issue.Summary,
					Severity:   issue.Severity,
					Cves:       convertSummaryCvesToCves(issue.Cves),
					Technology: issue.IssueType, // Store issue type in Technology field
				}
				
				// Preserve issue description in ExtendedInformation for JFrog research analysis
				if issue.Description != "" {
					vuln.ExtendedInformation = &services.ExtendedInformation{
						FullDescription: issue.Description,
					}
					// Log first 100 chars of description for debugging
					desc := issue.Description
					if len(desc) > 100 {
						desc = desc[:100] + "..."
					}
					log.Debug(fmt.Sprintf("Issue %s has description: '%s'", issue.IssueId, desc))
				}
				
				if issue.IssueType != "" {
					log.Debug(fmt.Sprintf("Issue %s has type: '%s'", issue.IssueId, issue.IssueType))
				}
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}
	
	log.Info(fmt.Sprintf("Extracted %d vulnerabilities from ArtifactSummary v1", len(vulnerabilities)))
	return vulnerabilities, nil
}

// Try using scan service for component scans
func tryScanServiceComponent(xrManager *xray.XrayServicesManager, artifactPath, sha256 string) ([]services.Vulnerability, error) {
	scanService := services.NewScanService(xrManager.Client())
	scanService.XrayDetails = xrManager.Config().GetServiceDetails()
	
	// Try to get existing scan results rather than trigger new scan
	// This might require different parameters or methods
	return nil, fmt.Errorf("scan service component approach not yet implemented")
}

// Try using build scan approach for Docker images
func tryBuildScan(xrManager *xray.XrayServicesManager, artifactPath, sha256 string) ([]services.Vulnerability, error) {
	// Docker images are often scanned as "builds" in Xray
	// This approach might be more appropriate for Docker containers
	return nil, fmt.Errorf("build scan approach not yet implemented")
}

func convertSummaryCvesToCves(summaryCves []services.SummaryCve) []services.Cve {
	var cves []services.Cve
	for _, sc := range summaryCves {
		cve := services.Cve{
			Id:          sc.Id,
			CvssV2Score: sc.CvssV2Score,
			CvssV3Score: sc.CvssV3Score,
			Cwe:         sc.Cwe,
		}
		cves = append(cves, cve)
	}
	return cves
}

// Data structures for v2 API response with enhanced component details
// These structures match the v2 artifact summary API response format as documented at:
// https://docs.jfrog.com/security/reference/artifact-summary_artifacts-v2-openapi

// ArtifactSummaryV2Response represents the top-level response from v2 API
type ArtifactSummaryV2Response struct {
	Artifacts []ArtifactV2 `json:"artifacts"` // List of artifacts with their vulnerability details
	Errors    []APIError   `json:"errors"`    // Any API errors for specific artifacts
}

type ArtifactV2 struct {
	General GeneralV2 `json:"general"`
	Issues  []IssueV2 `json:"issues"`
}

type GeneralV2 struct {
	Path        string `json:"path"`
	ComponentId string `json:"component_id"`
	PkgType     string `json:"pkg_type"`
}

// IssueV2 represents a security issue with enhanced component details
type IssueV2 struct {
	IssueId     string        `json:"issue_id"`     // Unique identifier for the security issue
	Summary     string        `json:"summary"`      // Human-readable description of the issue
	Description string        `json:"description"`  // Detailed description (may contain JFrog research)
	Severity    string        `json:"severity"`     // Severity level (Low, Medium, High, Critical)
	IssueType   string        `json:"issue_type"`   // JFrog's official classification (security, malicious, etc.)
	Cves        []CveV2       `json:"cves"`         // Associated CVE information
	Components  []ComponentV2 `json:"components"`   // NEW IN V2: Details about affected components and fixes
}

type CveV2 struct {
	Id          string `json:"id"`
	CvssV2Score string `json:"cvss_v2_score"`
	CvssV3Score string `json:"cvss_v3_score"`
	Cwe         []string `json:"cwe"`
}

// ComponentV2 represents detailed information about a vulnerable component
// This is the key enhancement in v2 API - granular component-level vulnerability details
type ComponentV2 struct {
	ComponentId   string   `json:"component_id"`    // Name/ID of the vulnerable component (e.g., "openssl")
	Version       string   `json:"version"`         // Current version of the component with the vulnerability
	PkgType       string   `json:"pkg_type"`        // Package type (e.g., "deb", "rpm", "npm", etc.)
	FixedVersions []string `json:"fixed_versions"`  // NEW IN V2: Versions that fix this vulnerability
}

type APIError struct {
	Identifier string `json:"identifier"`
	Error      string `json:"error"`
}

// EventsAPIResponse represents the response from /xray/api/v2/events/{issue_id}
type EventsAPIResponse struct {
	IssueId         string `json:"issue_id"`
	MaliciousPackage bool   `json:"malicious_package"`
	// Add other fields as needed
}

// convertV2ResponseToVulnerabilities converts v2 API response to existing Vulnerability format
func convertV2ResponseToVulnerabilities(v2Response ArtifactSummaryV2Response) []services.Vulnerability {
	var vulnerabilities []services.Vulnerability
	
	for i, artifact := range v2Response.Artifacts {
		log.Info(fmt.Sprintf("Artifact %d: %s (Component: %s, Type: %s, Issues: %d)", 
			i+1, artifact.General.Path, artifact.General.ComponentId, 
			artifact.General.PkgType, len(artifact.Issues)))
		
		for _, issue := range artifact.Issues {
			// Convert v2 CVEs to legacy format
			var cves []services.Cve
			for _, cveV2 := range issue.Cves {
				cve := services.Cve{
					Id:          cveV2.Id,
					CvssV2Score: cveV2.CvssV2Score,
					CvssV3Score: cveV2.CvssV3Score,
					Cwe:         cveV2.Cwe,
				}
				cves = append(cves, cve)
			}
			
			// Create enhanced vulnerability with component details
			vuln := services.Vulnerability{
				IssueId:    issue.IssueId,
				Summary:    issue.Summary,
				Severity:   issue.Severity,
				Cves:       cves,
				Technology: issue.IssueType, // Store issue type in Technology field
			}
			
			// Preserve issue description in ExtendedInformation for JFrog research analysis
			if issue.Description != "" {
				vuln.ExtendedInformation = &services.ExtendedInformation{
					FullDescription: issue.Description,
				}
				// Log first 100 chars of description for debugging
				desc := issue.Description
				if len(desc) > 100 {
					desc = desc[:100] + "..."
				}
				log.Debug(fmt.Sprintf("Issue %s has description: '%s'", issue.IssueId, desc))
			}
			
			if issue.IssueType != "" {
				log.Debug(fmt.Sprintf("Issue %s has type: '%s'", issue.IssueId, issue.IssueType))
			}
			
			// Log component-level details (NEW IN V2 API - provides actionable remediation info)
			if len(issue.Components) > 0 {
				log.Info(fmt.Sprintf("  Issue %s affects %d components:", issue.IssueId, len(issue.Components)))
				for _, component := range issue.Components {
					fixedVersionsStr := strings.Join(component.FixedVersions, ", ")
					if fixedVersionsStr == "" {
						fixedVersionsStr = "None available"
					}
					// This enhanced detail helps users understand exactly which packages need updating
					// and what versions to upgrade to - a major improvement over v1 API
					log.Info(fmt.Sprintf("    - %s:%s (%s) | Fixed versions: %s", 
						component.ComponentId, component.Version, component.PkgType, fixedVersionsStr))
				}
			}
			
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}
	
	log.Info(fmt.Sprintf("Extracted %d vulnerabilities from ArtifactSummary v2", len(vulnerabilities)))
	return vulnerabilities
}



// getDockerImagePaths returns Docker manifest paths that Xray expects for Docker images
// Based on discovery that Xray expects paths like: docker/docker-local/jmhxraytest/11/manifest.json
func getDockerImagePaths(repoKey, imageName, tag string) []string {
	var paths []string
	
	// PRIMARY FORMAT: Docker package paths with manifest.json (CORRECT FORMAT!)
	// Based on user discovery: docker/docker-local/jmhxraytest/11/manifest.json
	paths = append(paths, fmt.Sprintf("docker/%s/%s/%s/manifest.json", repoKey, imageName, tag))
	paths = append(paths, fmt.Sprintf("docker/%s/%s/%s/list.manifest.json", repoKey, imageName, tag))
	
	// Alternative Docker package formats
	paths = append(paths, fmt.Sprintf("docker/%s/%s/%s", repoKey, imageName, tag))
	paths = append(paths, fmt.Sprintf("docker/%s/%s:%s", repoKey, imageName, tag))
	
	// Docker package without repo prefix (for multi-repo setups)
	paths = append(paths, fmt.Sprintf("docker/%s/%s/manifest.json", imageName, tag))
	paths = append(paths, fmt.Sprintf("docker/%s/%s/list.manifest.json", imageName, tag))
	
	// Standard Docker artifact paths (legacy formats - keeping for compatibility)
	paths = append(paths, fmt.Sprintf("%s/%s:%s", repoKey, imageName, tag))
	paths = append(paths, fmt.Sprintf("%s/%s/%s", repoKey, imageName, tag))
	
	// Image without repo prefix
	paths = append(paths, fmt.Sprintf("%s:%s", imageName, tag))
	paths = append(paths, fmt.Sprintf("%s/%s", imageName, tag))
	
	// Docker package ID format
	paths = append(paths, fmt.Sprintf("docker://%s:%s", imageName, tag))
	paths = append(paths, fmt.Sprintf("docker://%s", imageName))
	
	// Colon-separated repo format
	paths = append(paths, fmt.Sprintf("%s:%s/%s", repoKey, imageName, tag))
	
	// Library namespace (for official images)
	paths = append(paths, fmt.Sprintf("docker/%s/library/%s/%s/manifest.json", repoKey, imageName, tag))
	paths = append(paths, fmt.Sprintf("%s/library/%s:%s", repoKey, imageName, tag))
	
	// Alternative separators
	paths = append(paths, fmt.Sprintf("%s/%s-%s", repoKey, imageName, tag))
	paths = append(paths, fmt.Sprintf("%s/%s_%s", repoKey, imageName, tag))
	
	// URL-encoded formats (for special characters)
	if strings.Contains(imageName, "-") || strings.Contains(tag, "-") {
		paths = append(paths, fmt.Sprintf("docker%%2F%s%%2F%s%%2F%s%%2Fmanifest.json", repoKey, imageName, tag))
	}
	
	return paths
}

// parseArtifactPath splits an artifact path into repository and path components
// Examples: 
//   "docker-local/myimage:1.0" -> ("docker-local", "myimage:1.0")
//   "docker-local/myimage/1.0" -> ("docker-local", "myimage/1.0")
func parseArtifactPath(artifactPath string) (repo, path string) {
	parts := strings.SplitN(artifactPath, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", artifactPath
}

// parseArtifactRepo extracts the repository name from an artifact path
func parseArtifactRepo(artifactPath string) string {
	repo, _ := parseArtifactPath(artifactPath)
	if repo == "" {
		// If no separator found, assume the first part before any special characters is the repo
		if idx := strings.IndexAny(artifactPath, ":/"); idx > 0 {
			return artifactPath[:idx]
		}
	}
	return repo
}

func filterVulnerabilitiesBySeverity(xrManager *xray.XrayServicesManager, vulnerabilities []services.Vulnerability, minSeverity string) []services.Vulnerability {
	if minSeverity == "" {
		return vulnerabilities
	}

	severityOrder := map[string]int{
		"Low":       1,
		"Medium":    2,
		"High":      3,
		"Critical":  4,
		"Malicious": 5, // Highest severity level
	}

	minLevel, exists := severityOrder[minSeverity]
	if !exists {
		return vulnerabilities
	}

	var filtered []services.Vulnerability
	for _, vuln := range vulnerabilities {
		// Check if vulnerability meets severity threshold
		vulnLevel := 0
		if level, exists := severityOrder[vuln.Severity]; exists {
			vulnLevel = level
		}
		
		// Special case: if filtering for "Malicious", only show malicious content
		if minSeverity == "Malicious" {
			if isMaliciousWithCache(xrManager, vuln.IssueId) {
				filtered = append(filtered, vuln)
			}
		} else if vulnLevel >= minLevel {
			filtered = append(filtered, vuln)
		}
	}

	return filtered
}



// generateSecurityBanner creates a visual banner based on the security status of findings
func generateSecurityBanner(xrManager *xray.XrayServicesManager, report *VulnerabilityReport, minSeverity string) {
	// Deduplicate vulnerabilities to analyze the actual findings
	vulnMap := make(map[string]services.Vulnerability)
	for _, platform := range report.Platforms {
		for _, vuln := range platform.Vulnerabilities {
			if vuln.IssueId != "" {
				vulnMap[vuln.IssueId] = vuln
			}
		}
	}
	
	// Convert to slice and apply filters to match what would be displayed
	var allVulns []services.Vulnerability
	for _, vuln := range vulnMap {
		allVulns = append(allVulns, vuln)
	}
	
	// Apply the same filtering logic used for display
	filteredVulns := allVulns
	if minSeverity != "" {
				filteredVulns = filterVulnerabilitiesBySeverity(xrManager, filteredVulns, minSeverity)
	}
	
	// Determine banner type based on filtered findings
	hasMalicious := false
	hasFindings := len(filteredVulns) > 0
	
	// Check for malicious content in filtered results
	for _, vuln := range filteredVulns {
		if isMaliciousWithCache(xrManager, vuln.IssueId) {
			hasMalicious = true
			break
		}
	}
	
	// Generate appropriate banner
	if hasMalicious {
		// RED banner for malicious content
		fmt.Println("---")
		fmt.Println()
		fmt.Println("> [!CAUTION]")
		fmt.Println("> ## 🚨 MALICIOUS EXPLOIT PRESENT 🚨")
		fmt.Println("> **IMMEDIATE ACTION REQUIRED** - Malicious content detected in this image")
		fmt.Println()
		fmt.Println("![Malicious](https://img.shields.io/badge/SECURITY-MALICIOUS_EXPLOIT_PRESENT-red?style=for-the-badge&logo=shield&logoColor=white)")
		fmt.Println()
		fmt.Println("---")
		fmt.Println()
	} else if hasFindings {
		// YELLOW banner for CVEs present
		fmt.Println("---")
		fmt.Println()
		fmt.Println("> [!WARNING]")
		fmt.Println("> ## ⚠️ CVE's PRESENT")
		fmt.Println("> Security vulnerabilities found - review and remediate as needed")
		fmt.Println()
		fmt.Println("![CVEs Present](https://img.shields.io/badge/SECURITY-CVE'S_PRESENT-yellow?style=for-the-badge&logo=alert&logoColor=black)")
		fmt.Println()
		fmt.Println("---")
		fmt.Println()
	} else {
		// GREEN banner for clean image
		fmt.Println("---")
		fmt.Println()
		fmt.Println("> [!NOTE]")
		fmt.Println("> ## ✅ NO FINDINGS")
		fmt.Println("> No security issues found at the specified threshold - image appears clean")
		fmt.Println()
		fmt.Println("![No Findings](https://img.shields.io/badge/SECURITY-NO_FINDINGS-green?style=for-the-badge&logo=checkmark&logoColor=white)")
		fmt.Println()
		fmt.Println("---")
		fmt.Println()
	}
}

// Function to discover what artifacts exist in Xray for the repository
func discoverXrayArtifacts(xrManager *xray.XrayServicesManager, repoKey, imageName string) {
	log.Info("=== XRAY ARTIFACT DISCOVERY ===")
	log.Info("Since you mentioned the image has been scanned with 1 malicious item,")
	log.Info("let's find the exact path format Xray is using...")
	log.Info("")
	
	// Try to search for Docker manifest artifacts with correct paths
	searchPatterns := []string{
		fmt.Sprintf("docker/%s", repoKey),                              // docker/docker-local
		fmt.Sprintf("docker/%s/*", repoKey),                            // docker/docker-local/*
		fmt.Sprintf("docker/%s/%s", repoKey, imageName),                // docker/docker-local/jmhxraytest
		fmt.Sprintf("docker/%s/%s/*", repoKey, imageName),              // docker/docker-local/jmhxraytest/*
		fmt.Sprintf("docker/%s/%s/*/manifest.json", repoKey, imageName), // docker/docker-local/jmhxraytest/*/manifest.json
		fmt.Sprintf("*%s*", imageName),                                 // *jmhxraytest* (legacy)
	}
	
	for i, pattern := range searchPatterns {
		log.Info(fmt.Sprintf("Searching Xray for pattern %d: %s", i+1, pattern))
		
		// Try to get summary with a wildcard search
		summaryService := services.NewSummaryService(xrManager.Client())
		summaryService.XrayDetails = xrManager.Config().GetServiceDetails()
		
		params := services.ArtifactSummaryParams{
			Paths: []string{pattern},
		}
		
		summary, err := summaryService.GetArtifactSummary(params)
		if err != nil {
			log.Info(fmt.Sprintf("  Pattern %s failed: %v", pattern, err))
			continue
		}
		
		if summary != nil && len(summary.Artifacts) > 0 {
			log.Info(fmt.Sprintf("  Found %d artifacts for pattern %s:", len(summary.Artifacts), pattern))
			for j, artifact := range summary.Artifacts {
				if j < 10 { // Show first 10 artifacts to find our image
					issueCount := len(artifact.Issues)
					if issueCount > 0 {
						log.Info(fmt.Sprintf("    %d. %s (%d issues) ⚠️", j+1, artifact.General.Path, issueCount))
						// If this might be our target image, show more details
						if strings.Contains(artifact.General.Path, imageName) {
							log.Info(fmt.Sprintf("        *** POTENTIAL MATCH FOR %s ***", imageName))
							for k, issue := range artifact.Issues {
								if k < 3 { // Show first 3 issues
									log.Info(fmt.Sprintf("        Issue %d: %s (%s)", k+1, issue.Summary, issue.Severity))
								}
							}
						}
					} else {
						log.Info(fmt.Sprintf("    %d. %s (no issues)", j+1, artifact.General.Path))
					}
				}
			}
			if len(summary.Artifacts) > 10 {
				log.Info(fmt.Sprintf("    ... and %d more", len(summary.Artifacts)-10))
			}
		} else {
			log.Info(fmt.Sprintf("  No artifacts found for pattern: %s", pattern))
		}
	}
	
	log.Info("=== END XRAY ARTIFACT DISCOVERY ===")
	log.Info("")
	log.Info("TROUBLESHOOTING RECOMMENDATIONS:")
	log.Info("1. Verify the image has been scanned by Xray")
	log.Info("2. Check Xray indexing configuration for the repository")
	log.Info(fmt.Sprintf("3. Expected Xray path format: docker/%s/%s/<tag>/manifest.json", repoKey, imageName))
	log.Info(fmt.Sprintf("4. Trigger manual scan: jf rt curl -XPOST '/api/v1/scan/graph' -H 'Content-Type: application/json' -d '{\"component_details\":{\"component_id\":\"docker/%s/%s\"}}' --server-id <server-id>", repoKey, imageName))
	log.Info("5. Check JFrog UI: Administration > Xray > Settings > Repositories")
	log.Info("6. Verify Docker images appear as 'docker/repo/image/tag/manifest.json' in Xray")
	log.Info("")
}

func outputReport(xrManager *xray.XrayServicesManager, report *VulnerabilityReport, output string, minSeverity string, showFindings bool) error {
	switch output {
	case "json":
		return outputJSONReport(xrManager, report)
	case "github-md":
		return outputMarkdownReport(xrManager, report, minSeverity, showFindings)
	default:
		return fmt.Errorf("unsupported output format: %s. Use 'json' or 'github-md'", output)
	}
}

// EnhancedVulnerabilityReport includes additional analysis for streamlined output
type EnhancedVulnerabilityReport struct {
	ImageName      string                        `json:"imageName"`
	GeneratedAt    string                        `json:"generatedAt"`
	Summary        SecuritySummary               `json:"summary"`
	IssueTypes     map[string]int                `json:"issueTypes"`
	Platforms      []EnhancedPlatformInfo        `json:"platforms"`
}

type SecuritySummary struct {
	TotalFindings   int `json:"totalFindings"`
	CriticalCount   int `json:"criticalCount"`
	HighCount       int `json:"highCount"`
	MediumCount     int `json:"mediumCount"`
	LowCount        int `json:"lowCount"`
	MaliciousCount  int `json:"maliciousCount"`
	PlatformCount   int `json:"platformCount"`
}

type EnhancedPlatformInfo struct {
	Platform      Platform               `json:"platform"`
	FindingsCount int                    `json:"findingsCount"`
	LayerCount    int                    `json:"layerCount"`
	SizeMB        float64                `json:"sizeMB"`
	Findings      []CompactFinding       `json:"findings"`
}

type CompactFinding struct {
	IssueId     string `json:"issueId"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Malicious   bool   `json:"malicious"`
	CveCount    int    `json:"cveCount"`
}

func outputJSONReport(xrManager *xray.XrayServicesManager, report *VulnerabilityReport) error {
	// Convert to enhanced format
	enhanced := convertToEnhancedReport(xrManager, report)
	
	jsonData, err := json.MarshalIndent(enhanced, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	
	fmt.Println(string(jsonData))
	return nil
}

func convertToEnhancedReport(xrManager *xray.XrayServicesManager, report *VulnerabilityReport) *EnhancedVulnerabilityReport {
	
	typeCount := make(map[string]int)
	maliciousCount := 0
	
	var platforms []EnhancedPlatformInfo
	
	for _, platform := range report.Platforms {
		var findings []CompactFinding
		
		for _, vuln := range platform.Vulnerabilities {
			issueType := extractIssueType(vuln)
			if issueType == "" {
				issueType = "Security"
			}
			typeCount[issueType]++
			

			malicious := isMaliciousWithCache(xrManager, vuln.IssueId)
			if malicious {
				maliciousCount++
			}
			
			finding := CompactFinding{
				IssueId:   vuln.IssueId,
				Type:      issueType,
				Severity:  vuln.Severity,
				Malicious: malicious,
				CveCount:  len(vuln.Cves),
			}
			findings = append(findings, finding)
		}
		
		enhancedPlatform := EnhancedPlatformInfo{
			Platform:      platform.Platform,
			FindingsCount: len(platform.Vulnerabilities),
			LayerCount:    platform.LayerCount,
			SizeMB:        float64(platform.TotalSize) / (1024 * 1024),
			Findings:      findings,
		}
		platforms = append(platforms, enhancedPlatform)
	}
	
	return &EnhancedVulnerabilityReport{
		ImageName:   report.ImageName,
		GeneratedAt: report.GeneratedAt,
		Summary: SecuritySummary{
			TotalFindings:  report.TotalIssues,
			CriticalCount:  report.CriticalCount,
			HighCount:      report.HighCount,
			MediumCount:    report.MediumCount,
			LowCount:       report.LowCount,
			MaliciousCount: maliciousCount,
			PlatformCount:  len(report.Platforms),
		},
		IssueTypes: typeCount,
		Platforms:  platforms,
	}
}

func outputMarkdownReport(xrManager *xray.XrayServicesManager, report *VulnerabilityReport, minSeverity string, showFindings bool) error {
	fmt.Printf("# Xray Security Report: %s\n\n", report.ImageName)

	// Generate security status banner before anything else
	generateSecurityBanner(xrManager, report, minSeverity)

	// Security Summary with counts
	fmt.Println("## Security Summary")
	
	// Deduplicate vulnerabilities across all platforms for accurate counting and display
	vulnMap := make(map[string]services.Vulnerability)
	typeCount := make(map[string]int)
	maliciousCount := 0
	
	for _, platform := range report.Platforms {
		for _, vuln := range platform.Vulnerabilities {
			// Use Xray ID as key to ensure each unique vulnerability is counted only once
			if vuln.IssueId != "" {
				vulnMap[vuln.IssueId] = vuln
			}
		}
	}
	
	// Now count the unique vulnerabilities
	for _, vuln := range vulnMap {
		// Extract type information if available
		issueType := extractIssueType(vuln)
		if issueType != "" {
			typeCount[issueType]++
		} else {
			typeCount["Security"]++ // Default for vulnerabilities
		}
		
		// Check for malicious indicators using Events API
		if isMaliciousWithCache(xrManager, vuln.IssueId) {
			maliciousCount++
			log.Info(fmt.Sprintf("🚨 Found malicious package: %s (ID: %s)", vuln.Summary, vuln.IssueId))
		}
	}
	
	log.Info(fmt.Sprintf("📊 Malicious detection summary: Checked %d unique vulnerabilities, found %d malicious packages", len(vulnMap), maliciousCount))
	
	uniqueVulnCount := len(vulnMap)
	fmt.Printf("- **Total Findings:** %d\n", uniqueVulnCount)
	fmt.Printf("- **Critical:** %d | **High:** %d | **Medium:** %d | **Low:** %d\n", 
		report.CriticalCount, report.HighCount, report.MediumCount, report.LowCount)
	fmt.Printf("- **Malicious:** %d\n", maliciousCount)
	fmt.Printf("- **Platforms Scanned:** %d\n\n", len(report.Platforms))

	// Display consolidated findings table with optional severity filtering
	if showFindings {
		if uniqueVulnCount > 0 {
			// Convert map to slice for filtering
			var allVulns []services.Vulnerability
			for _, vuln := range vulnMap {
				allVulns = append(allVulns, vuln)
			}
			
			// Apply filtering to displayed findings (not to summary counts)
			filteredVulns := allVulns
			
			// Apply severity filtering
			if minSeverity != "" {
		filteredVulns = filterVulnerabilitiesBySeverity(xrManager, filteredVulns, minSeverity)
			}
			
			fmt.Println("## Security Findings")
			
			// Build filter description
			var filterDesc []string
			if minSeverity != "" {
				filterDesc = append(filterDesc, fmt.Sprintf("min-severity: %s", minSeverity))
			}
			
			if len(filterDesc) > 0 {
				fmt.Printf("📊 **%d vulnerabilities found** | 🔽 **%d displayed** (%s) | 📁 **%d platform(s)**\n\n", 
					uniqueVulnCount, len(filteredVulns), strings.Join(filterDesc, ", "), len(report.Platforms))
			} else {
				fmt.Printf("📊 **%d unique vulnerabilities found across %d platform(s)**\n\n", 
					uniqueVulnCount, len(report.Platforms))
			}
			
			if len(filteredVulns) > 0 {
				// Consolidated findings table
				fmt.Println("| Xray ID | Type | Severity | Malicious |")
				fmt.Println("|---------|------|----------|-----------|")
				
				for _, vuln := range filteredVulns {
					issueType := extractIssueType(vuln)
					if issueType == "" {
						issueType = "Security"
					}
					
					maliciousIcon := "❌"
		if isMaliciousWithCache(xrManager, vuln.IssueId) {
						maliciousIcon = "🚨"
					}
					
					severityIcon := getSeverityIcon(vuln.Severity)
					
					fmt.Printf("| %s | %s | %s %s | %s |\n", 
						vuln.IssueId,
						issueType,
						severityIcon,
						vuln.Severity,
						maliciousIcon)
				}
				fmt.Println()
			} else {
				if len(filterDesc) > 0 {
					fmt.Printf("🔽 **No vulnerabilities match filters: %s**\n\n", strings.Join(filterDesc, ", "))
				} else {
					fmt.Printf("🔽 **No vulnerabilities to display**\n\n")
				}
			}
		} else {
			fmt.Println("## Security Findings")
			fmt.Println("✅ **No security issues found**\n")
		}
	}

	return nil
}

// Missing functions - minimal implementations

func parseImageName(imageName string) (string, string, string, error) {
	// Parse docker-local/image:tag format
	parts := strings.Split(imageName, "/")
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("invalid image format, expected: repo/image:tag")
	}
	
	repoKey := parts[0]
	imageAndTag := strings.Join(parts[1:], "/")
	
	// Split image and tag
	tagParts := strings.Split(imageAndTag, ":")
	if len(tagParts) < 2 {
		return repoKey, tagParts[0], "latest", nil
	}
	
	image := strings.Join(tagParts[:len(tagParts)-1], ":")
	tag := tagParts[len(tagParts)-1]
	
	return repoKey, image, tag, nil
}

func getServerDetails(serverId string) (*config.ServerDetails, error) {
	return config.GetSpecificConfig(serverId, true, false)
}

func setupArtifactory(serverDetails *config.ServerDetails) (artifactory.ArtifactoryServicesManager, error) {
	artAuth := artifactoryAuth.NewArtifactoryDetails()
	artAuth.SetUrl(serverDetails.GetArtifactoryUrl())
	artAuth.SetAccessToken(serverDetails.GetAccessToken())
	artAuth.SetUser(serverDetails.GetUser())
	artAuth.SetPassword(serverDetails.GetPassword())
	
	serviceConfig, err := clientconfig.NewConfigBuilder().
		SetServiceDetails(artAuth).
		Build()
	if err != nil {
		return nil, err
	}
	
	return artifactory.New(serviceConfig)
}

func setupXray(serverDetails *config.ServerDetails) (*xray.XrayServicesManager, error) {
	xrayAuthDetails := xrayAuth.NewXrayDetails()
	
	// Convert Artifactory URL to Xray URL
	artUrl := serverDetails.GetArtifactoryUrl()
	xrayUrl := strings.Replace(artUrl, "/artifactory", "/xray", 1)
	if !strings.Contains(xrayUrl, "/xray") {
		baseUrl := strings.TrimSuffix(artUrl, "/artifactory")
		baseUrl = strings.TrimSuffix(baseUrl, "/")
		xrayUrl = baseUrl + "/xray"
	}
	
	xrayAuthDetails.SetUrl(xrayUrl)
	xrayAuthDetails.SetAccessToken(serverDetails.GetAccessToken())
	xrayAuthDetails.SetUser(serverDetails.GetUser())
	xrayAuthDetails.SetPassword(serverDetails.GetPassword())
	
	serviceConfig, err := clientconfig.NewConfigBuilder().
		SetServiceDetails(xrayAuthDetails).
		Build()
	if err != nil {
		return nil, err
	}
	
	return xray.New(serviceConfig)
}

func exploreRepositoryStructure(rtManager artifactory.ArtifactoryServicesManager, repoKey, imageName, tag string) error {
	// Placeholder - not essential for core functionality
	log.Debug("Repository structure exploration not implemented")
	return nil
}

func createDockerRegistryClient(conf *checkConfiguration, serverDetails *config.ServerDetails) (*DockerRegistryClient, error) {
	baseURL := conf.dockerRegistryURL
	if baseURL == "" {
		// Construct from server details
		artUrl := serverDetails.GetArtifactoryUrl()
		baseURL = strings.Replace(artUrl, "/artifactory", "", 1)
		baseURL = strings.TrimSuffix(baseURL, "/")
	}
	
	return &DockerRegistryClient{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		Username:   serverDetails.GetUser(),
		Password:   serverDetails.GetPassword(),
	}, nil
}

func generateVulnerabilityReport(conf *checkConfiguration, rtManager artifactory.ArtifactoryServicesManager, xrManager *xray.XrayServicesManager, client *DockerRegistryClient, repoKey, imageName, tag string) (*VulnerabilityReport, error) {
	if !conf.silent {
		log.Info(fmt.Sprintf("Generating vulnerability report for %s/%s:%s", repoKey, imageName, tag))
	}
	
	report := &VulnerabilityReport{
		ImageName:   fmt.Sprintf("%s/%s:%s", repoKey, imageName, tag),
		GeneratedAt: time.Now().Format(time.RFC3339),
		Platforms:   []PlatformVulnerabilityInfo{},
	}
	
	// Generate potential Docker image paths for Xray scanning
	dockerPaths := getDockerImagePaths(repoKey, imageName, tag)
	if !conf.silent {
		log.Info(fmt.Sprintf("Trying %d different Docker path formats", len(dockerPaths)))
	}
	
	// Use a map to deduplicate vulnerabilities by Xray ID
	vulnMap := make(map[string]services.Vulnerability)
	var successfulPath string
	
	// Try each Docker path format until we get vulnerability data
	for _, path := range dockerPaths {
		if !conf.silent {
			log.Debug(fmt.Sprintf("Trying path: %s", path))
		}
		
		// Try V2 API first (preferred)
		vulns, err := tryArtifactSummaryV2(xrManager, path, "")
		if err == nil && len(vulns) > 0 {
			// Add vulnerabilities to map (deduplicating by IssueId)
			beforeCount := len(vulnMap)
			for _, vuln := range vulns {
				if vuln.IssueId != "" {
					vulnMap[vuln.IssueId] = vuln
				}
			}
			afterCount := len(vulnMap)
			if successfulPath == "" {
				successfulPath = path
			}
			if !conf.silent {
				log.Info(fmt.Sprintf("Found %d vulnerabilities using V2 API with path: %s", len(vulns), path))
				if beforeCount != afterCount {
					log.Info(fmt.Sprintf("Added %d new unique vulnerabilities (total unique: %d)", afterCount-beforeCount, afterCount))
				}
			}
			break // Found data, stop trying more paths
		}
		
		// Fallback to V1 API
		vulns, err = tryArtifactSummary(xrManager, path, "")
		if err == nil && len(vulns) > 0 {
			// Add vulnerabilities to map (deduplicating by IssueId)
			beforeCount := len(vulnMap)
			for _, vuln := range vulns {
				if vuln.IssueId != "" {
					vulnMap[vuln.IssueId] = vuln
				}
			}
			afterCount := len(vulnMap)
			if successfulPath == "" {
				successfulPath = path
			}
			if !conf.silent {
				log.Info(fmt.Sprintf("Found %d vulnerabilities using V1 API with path: %s", len(vulns), path))
				if beforeCount != afterCount {
					log.Info(fmt.Sprintf("Added %d new unique vulnerabilities (total unique: %d)", afterCount-beforeCount, afterCount))
				}
			}
			break // Found data, stop trying more paths
		}
		
		if !conf.silent {
			log.Debug(fmt.Sprintf("No data found for path: %s", path))
		}
	}
	
	// Convert map back to slice for processing
	var allVulns []services.Vulnerability
	for _, vuln := range vulnMap {
		allVulns = append(allVulns, vuln)
	}
	
	// If no vulnerabilities found through direct paths, try discovery approach
	if len(allVulns) == 0 {
		if !conf.silent {
			log.Info("Direct path lookup failed, trying discovery approach...")
			// Run discovery for debugging (doesn't return artifacts, just logs)
			discoverXrayArtifacts(xrManager, repoKey, imageName)
		}
	}
	
	// Process vulnerabilities into platform-specific groups
	if len(allVulns) > 0 {
		// For now, group all vulns under a single platform since we don't have manifest parsing
		// In a full implementation, you'd parse Docker manifests to get platform-specific data
		platformInfo := PlatformVulnerabilityInfo{
			Platform: Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
			Vulnerabilities: allVulns, // Use the raw vulnerabilities from Xray
		}
		
		report.Platforms = append(report.Platforms, platformInfo)
		
		// Calculate summary counts
		report.TotalIssues = len(allVulns)
		for _, vuln := range allVulns {
			switch vuln.Severity {
			case "Critical":
				report.CriticalCount++
			case "High":
				report.HighCount++
			case "Medium":
				report.MediumCount++
			case "Low":
				report.LowCount++
			}
		}
		
		if successfulPath != "" && !conf.silent {
			log.Info(fmt.Sprintf("Successfully generated report with %d vulnerabilities from path: %s", 
				len(allVulns), successfulPath))
		}
	} else {
		if !conf.silent {
			log.Info("No vulnerabilities found for this image")
		}
	}
	
	return report, nil
}



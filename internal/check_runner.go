// check will search for vulnerabilities in the specified image and generate a report based on existing scans
package internal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/artifactory"
	artifactoryAuth "github.com/jfrog/jfrog-client-go/artifactory/auth"
	clientconfig "github.com/jfrog/jfrog-client-go/config"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray"
	xrayAuth "github.com/jfrog/jfrog-client-go/xray/auth"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

// Constants for media types
const (
	MediaTypeManifest     = "application/vnd.docker.distribution.manifest.v2+json"
	MediaTypeManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
	MediaTypeOCIManifest  = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeOCIIndex     = "application/vnd.oci.image.index.v1+json"
)

func RunCheckCommand(c *components.Context) error {
	if len(c.Arguments) == 0 {
		return fmt.Errorf("image name is required. Usage: check <image:tag>")
	}
	if len(c.Arguments) > 1 {
		return fmt.Errorf("too many arguments. Expected: check <image:tag>")
	}

	output := c.GetStringFlagValue("output")
	if output == "" {
		output = "json" // Default to JSON
	}

	conf := &CheckConfiguration{
		ImageName:         c.Arguments[0],
		ServerId:          c.GetStringFlagValue("server-id"),
		Platform:          c.GetStringFlagValue("platform"),
		OS:                c.GetStringFlagValue("os"),
		FailOnVuln:        c.GetBoolFlagValue("fail-on-vuln"),
		Output:            output,
		Silent:            output == "github-md",
		MinSeverity:       c.GetStringFlagValue("min-severity"),
		ShowFindings:      c.GetBoolFlagValue("show-findings"),
		DebugPaths:        c.GetBoolFlagValue("debug-paths"),
		DockerRegistryURL: c.GetStringFlagValue("docker-registry-url"),
	}

	// Configure log level based on output format
	if conf.Silent {
		// In silent mode (github-md output), only show ERROR messages
		log.SetLogger(log.NewLogger(log.ERROR, os.Stderr))
	}

	// Parse image name to extract repository and tag
	repoKey, imageName, tag, err := parseImageName(conf.ImageName)
	if err != nil {
		return fmt.Errorf("invalid image format: %w", err)
	}

	// Only log if not in silent mode
	if !conf.Silent {
		log.Info(fmt.Sprintf("Checking vulnerabilities for image: %s/%s:%s", repoKey, imageName, tag))
	}

	// Setup JFrog service connections
	serverDetails, err := getServerDetails(conf.ServerId)
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
	if err := outputReport(xrManager, report, conf.Output, conf.MinSeverity, conf.ShowFindings); err != nil {
		return fmt.Errorf("failed to output report: %w", err)
	}

	// Check if we should fail on vulnerabilities
	if conf.FailOnVuln && report.TotalIssues > 0 {
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
	eventsEndpoint := buildXrayAPIEndpoint(xrayDetails.GetUrl(), fmt.Sprintf("/api/v2/events/%s", url.PathEscape(issueId)))

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

	isMalicious, foundField, err := parseMaliciousPackageFromEventsResponse(body)
	if err != nil {
		log.Warn(fmt.Sprintf("Failed to parse Events API response for %s: %v", issueId, err))
		return false, err
	}
	if !foundField {
		log.Debug(fmt.Sprintf("Events API response for %s does not include malicious_package", issueId))
		return false, nil
	}
	log.Debug(fmt.Sprintf("Issue %s malicious_package field: %t", issueId, isMalicious))
	return isMalicious, nil
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

func getArtifactSummaryVulnerabilities(xrManager *xray.XrayServicesManager, artifactPath, sha256 string) ([]services.Vulnerability, error) {
	log.Info(fmt.Sprintf("Querying Xray summary for path: %s", artifactPath))

	summaryService := services.NewSummaryService(xrManager.Client())
	xrayDetails := xrManager.Config().GetServiceDetails()
	summaryService.XrayDetails = xrayDetails

	params := services.ArtifactSummaryParams{
		Paths: []string{artifactPath},
	}

	if sha256 != "" {
		params.Checksums = []string{sha256}
		log.Info(fmt.Sprintf("Including checksum: %s", sha256))
	}

	log.Info(fmt.Sprintf("Making Xray SDK summary call to: %s", xrayDetails.GetUrl()))

	summary, err := summaryService.GetArtifactSummary(params)
	if err != nil {
		log.Warn(fmt.Sprintf("Xray summary call failed: %v", err))
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

	log.Info(fmt.Sprintf("Xray summary found %d artifacts", len(summary.Artifacts)))

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

	log.Info(fmt.Sprintf("Extracted %d vulnerabilities from Xray summary", len(vulnerabilities)))
	return vulnerabilities, nil
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

func parseMaliciousPackageFromEventsResponse(body []byte) (isMalicious bool, foundField bool, err error) {
	var payload interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return false, false, err
	}

	values := findMaliciousPackageFields(payload)
	if len(values) == 0 {
		return false, false, nil
	}
	for _, value := range values {
		if value {
			return true, true, nil
		}
	}
	return false, true, nil
}

func findMaliciousPackageFields(v interface{}) []bool {
	var values []bool
	switch typed := v.(type) {
	case map[string]interface{}:
		if raw, ok := typed["malicious_package"]; ok {
			if malicious, ok := parseBooleanLike(raw); ok {
				values = append(values, malicious)
			}
		}
		for _, nested := range typed {
			values = append(values, findMaliciousPackageFields(nested)...)
		}
	case []interface{}:
		for _, nested := range typed {
			values = append(values, findMaliciousPackageFields(nested)...)
		}
	}
	return values
}

func parseBooleanLike(value interface{}) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		normalized := strings.TrimSpace(strings.ToLower(typed))
		if normalized == "true" || normalized == "1" || normalized == "yes" {
			return true, true
		}
		if normalized == "false" || normalized == "0" || normalized == "no" {
			return false, true
		}
	case float64:
		if typed == 1 {
			return true, true
		}
		if typed == 0 {
			return false, true
		}
	}
	return false, false
}

func collectUniqueIssueIDs(report *VulnerabilityReport) []string {
	issueIDSet := make(map[string]struct{})
	for _, platform := range report.Platforms {
		for _, vuln := range platform.Vulnerabilities {
			if vuln.IssueId == "" {
				continue
			}
			issueIDSet[vuln.IssueId] = struct{}{}
		}
	}

	issueIDs := make([]string, 0, len(issueIDSet))
	for issueID := range issueIDSet {
		issueIDs = append(issueIDs, issueID)
	}
	return issueIDs
}

func countMaliciousIssuesFromEvents(xrManager *xray.XrayServicesManager, issueIDs []string) int {
	count := 0
	for _, issueID := range issueIDs {
		if isMaliciousWithCache(xrManager, issueID) {
			count++
		}
	}
	return count
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
//
//	"docker-local/myimage:1.0" -> ("docker-local", "myimage:1.0")
//	"docker-local/myimage/1.0" -> ("docker-local", "myimage/1.0")
func parseArtifactPath(artifactPath string) (repo, path string) {
	parts := strings.SplitN(artifactPath, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", artifactPath
}

func filterVulnerabilitiesBySeverity(vulnerabilities []services.Vulnerability, minSeverity string, xrManagers ...*xray.XrayServicesManager) []services.Vulnerability {
	if minSeverity == "" {
		return vulnerabilities
	}
	var xrManager *xray.XrayServicesManager
	if len(xrManagers) > 0 {
		xrManager = xrManagers[0]
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
			if xrManager != nil && isMaliciousWithCache(xrManager, vuln.IssueId) {
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
		filteredVulns = filterVulnerabilitiesBySeverity(filteredVulns, minSeverity, xrManager)
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
		fmt.Sprintf("docker/%s", repoKey),                               // docker/docker-local
		fmt.Sprintf("docker/%s/*", repoKey),                             // docker/docker-local/*
		fmt.Sprintf("docker/%s/%s", repoKey, imageName),                 // docker/docker-local/jmhxraytest
		fmt.Sprintf("docker/%s/%s/*", repoKey, imageName),               // docker/docker-local/jmhxraytest/*
		fmt.Sprintf("docker/%s/%s/*/manifest.json", repoKey, imageName), // docker/docker-local/jmhxraytest/*/manifest.json
		fmt.Sprintf("*%s*", imageName),                                  // *jmhxraytest* (legacy)
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
	issueIDs := collectUniqueIssueIDs(report)
	maliciousCount := countMaliciousIssuesFromEvents(xrManager, issueIDs)

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

	for _, platform := range report.Platforms {
		for _, vuln := range platform.Vulnerabilities {
			// Use Xray ID as key to ensure each unique vulnerability is counted only once
			if vuln.IssueId != "" {
				vulnMap[vuln.IssueId] = vuln
			}
		}
	}
	issueIDs := make([]string, 0, len(vulnMap))
	for issueID := range vulnMap {
		issueIDs = append(issueIDs, issueID)
	}
	maliciousCount := countMaliciousIssuesFromEvents(xrManager, issueIDs)

	// Now count the unique vulnerabilities
	for _, vuln := range vulnMap {
		// Extract type information if available
		issueType := extractIssueType(vuln)
		if issueType != "" {
			typeCount[issueType]++
		} else {
			typeCount["Security"]++ // Default for vulnerabilities
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
				filteredVulns = filterVulnerabilitiesBySeverity(filteredVulns, minSeverity, xrManager)
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
			fmt.Println("✅ **No security issues found**")
			fmt.Println()
		}
	}

	return nil
}

// Missing functions - minimal implementations

func parseImageName(imageName string) (string, string, string, error) {
	trimmed := strings.TrimSpace(imageName)
	if trimmed == "" {
		return "", "", "", fmt.Errorf("invalid image format, expected: repo/image:tag")
	}

	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", fmt.Errorf("invalid image format, expected: repo/image:tag")
	}

	repoKey := parts[0]
	imageAndTag := parts[1]
	tagSeparator := strings.LastIndex(imageAndTag, ":")
	if tagSeparator <= 0 || tagSeparator == len(imageAndTag)-1 {
		return "", "", "", fmt.Errorf("invalid image format, expected: repo/image:tag")
	}

	image := imageAndTag[:tagSeparator]
	tag := imageAndTag[tagSeparator+1:]
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

	xrayUrl := getXrayServiceURL(serverDetails)

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

func getXrayServiceURL(serverDetails *config.ServerDetails) string {
	if configuredXrayURL := strings.TrimSpace(serverDetails.GetXrayUrl()); configuredXrayURL != "" {
		return strings.TrimSuffix(configuredXrayURL, "/")
	}

	if artifactoryURL := strings.TrimSpace(serverDetails.GetArtifactoryUrl()); artifactoryURL != "" {
		if strings.Contains(artifactoryURL, "/artifactory") {
			return strings.TrimSuffix(strings.Replace(artifactoryURL, "/artifactory", "/xray", 1), "/")
		}
		return strings.TrimSuffix(artifactoryURL, "/") + "/xray"
	}

	return strings.TrimSuffix(strings.TrimSpace(serverDetails.GetUrl()), "/") + "/xray"
}

func buildXrayAPIEndpoint(xrayServiceURL, path string) string {
	base := strings.TrimSuffix(strings.TrimSpace(xrayServiceURL), "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if strings.HasSuffix(base, "/xray") {
		return base + path
	}
	return base + "/xray" + path
}

func createDockerRegistryClient(conf *CheckConfiguration, serverDetails *config.ServerDetails) (*DockerRegistryClient, error) {
	baseURL := conf.DockerRegistryURL
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

func generateVulnerabilityReport(conf *CheckConfiguration, rtManager artifactory.ArtifactoryServicesManager, xrManager *xray.XrayServicesManager, client *DockerRegistryClient, repoKey, imageName, tag string) (*VulnerabilityReport, error) {
	if !conf.Silent {
		log.Info(fmt.Sprintf("Generating vulnerability report for %s/%s:%s", repoKey, imageName, tag))
	}

	report := &VulnerabilityReport{
		ImageName:   fmt.Sprintf("%s/%s:%s", repoKey, imageName, tag),
		GeneratedAt: time.Now().Format(time.RFC3339),
		Platforms:   []PlatformVulnerabilityInfo{},
	}

	// Generate potential Docker image paths for Xray scanning
	dockerPaths := getDockerImagePaths(repoKey, imageName, tag)
	if !conf.Silent {
		log.Info(fmt.Sprintf("Trying %d different Docker path formats", len(dockerPaths)))
	}

	// Use a map to deduplicate vulnerabilities by Xray ID
	vulnMap := make(map[string]services.Vulnerability)
	var successfulPath string

	// Try each Docker path format until we get vulnerability data
	for _, path := range dockerPaths {
		if !conf.Silent {
			log.Debug(fmt.Sprintf("Trying path: %s", path))
		}

		// Query vulnerabilities using Xray SummaryService from the JFrog Go SDK.
		vulns, err := getArtifactSummaryVulnerabilities(xrManager, path, "")
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
			if !conf.Silent {
				log.Info(fmt.Sprintf("Found %d vulnerabilities using Xray SummaryService with path: %s", len(vulns), path))
				if beforeCount != afterCount {
					log.Info(fmt.Sprintf("Added %d new unique vulnerabilities (total unique: %d)", afterCount-beforeCount, afterCount))
				}
			}
			break // Found data, stop trying more paths
		}

		if !conf.Silent {
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
		if !conf.Silent {
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

		if successfulPath != "" && !conf.Silent {
			log.Info(fmt.Sprintf("Successfully generated report with %d vulnerabilities from path: %s",
				len(allVulns), successfulPath))
		}
	} else {
		if !conf.Silent {
			log.Info("No vulnerabilities found for this image")
		}
	}

	return report, nil
}

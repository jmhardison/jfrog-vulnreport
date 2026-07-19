// check will search for vulnerabilities in the specified image and generate a report based on existing scans
package internal

import (
	"encoding/json"
	"fmt"
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
		ProjectKey:        c.GetStringFlagValue("project-key"),
	}

	// Default project key to "default" if not specified
	if conf.ProjectKey == "" {
		conf.ProjectKey = "default"
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

	// Generate vulnerability report (all Xray queries use CLI wrappers in internal/xray_cli.go)
	report, err := generateVulnerabilityReport(conf, rtManager, repoKey, imageName, tag)
	if err != nil {
		return fmt.Errorf("failed to generate vulnerability report: %w", err)
	}

	// Output the report
	if err := outputReport(conf.ServerId, report, conf.Output, conf.MinSeverity, conf.ShowFindings); err != nil {
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

// checkMaliciousPackage queries the JFrog Events API to check if an issue is malicious.
// Always uses CLI-based approach since direct SDK access fails due to JWT audience restrictions.
func checkMaliciousPackage(serverId string, issueId string) (bool, error) {
	if issueId == "" {
		return false, nil
	}

	isMalicious, err := checkMaliciousPackageCLI(serverId, issueId)
	if err != nil {
		log.Debug(fmt.Sprintf("CLI Events API failed for %s: %v", issueId, err))
		return false, err
	}

	return isMalicious, nil
}

// isMaliciousWithCache checks if an issue is malicious using Events API with caching.
var maliciousCache = make(map[string]bool)
var maliciousCacheMutex sync.RWMutex

func isMaliciousWithCache(serverId string, issueId string) bool {
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

	isMalicious, err := checkMaliciousPackage(serverId, issueId)
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



// getArtifactSummaryVulnerabilitiesCLI queries Xray Violations API using JFrog CLI subprocess to bypass JWT audience restrictions.
// Replaced SummaryService (/api/v1/summary/artifact) which hangs indefinitely for Docker images with Violations API (/api/v1/violations).
func getArtifactSummaryVulnerabilitiesCLI(serverId, projectKey, artifactPath string) ([]services.Vulnerability, error) {
	log.Info(fmt.Sprintf("Querying Xray Violations API via CLI for path: %s (project: %s)", artifactPath, projectKey))

	// Use the correct Violations API endpoint instead of SummaryService (which hangs for Docker images)
	vulns, err := queryXrayViolationsViaCLIVulnerabilities(serverId, projectKey, artifactPath)
	if err != nil {
		return nil, fmt.Errorf("failed to query Xray Violations API via CLI: %w", err)
	}

	log.Info(fmt.Sprintf("Extracted %d vulnerabilities from Violations API response", len(vulns)))
	return vulns, nil
}

// convertCLICvesToCves converts CVEs from CLI format to SDK Vulnerability.Cves format
func convertCLICvesToCves(cliCves []xrayCve) []services.Cve {
	var cves []services.Cve
	for _, cc := range cliCves {
		cve := services.Cve{
			Id:          cc.Id,
			CvssV2Score: cc.CvssV2Score,
			CvssV3Score: cc.CvssV3Score,
			Cwe:         cc.Cwe,
		}
		cves = append(cves, cve)
	}
	return cves
}

// checkMaliciousPackageCLI checks if an issue is malicious using JFrog CLI Events API.
func checkMaliciousPackageCLI(serverId string, issueId string) (bool, error) {
	if issueId == "" {
		return false, nil
	}

	isMalicious, err := queryXrayEventsViaCLI(serverId, issueId)
	if err != nil {
		log.Debug(fmt.Sprintf("Failed to query Events API via CLI for %s: %v", issueId, err))
		return false, err
	}

	if isMalicious {
		log.Info(fmt.Sprintf("🚨 JFrog CLI confirmed malicious package: %s", issueId))
	}

	return isMalicious, nil
}

// parseMaliciousPackageFromEventsResponse extracts malicious package status from Events API response.
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

// prefetchMaliciousStatuses queries the Events API for all unique issue IDs concurrently.
// This batches what would otherwise be N sequential HTTP calls into parallel requests.
func prefetchMaliciousStatuses(serverId string, issueIDs []string) {
	var wg sync.WaitGroup

	for _, issueID := range issueIDs {
		if issueID == "" {
			continue
		}

		maliciousCacheMutex.RLock()
		_, exists := maliciousCache[issueID]
		maliciousCacheMutex.RUnlock()

		if !exists {
			wg.Add(1)
			go func(id string) {
				defer wg.Done()
				isMalicious, err := checkMaliciousPackage(serverId, id)
				if err != nil {
					log.Debug(fmt.Sprintf("Events API error for %s: %v", id, err))
					return
				}

				if isMalicious {
					log.Info(fmt.Sprintf("🚨 Events API confirmed malicious package: %s", id))
				}

				maliciousCacheMutex.Lock()
				maliciousCache[id] = isMalicious
				maliciousCacheMutex.Unlock()
			}(issueID)
		}
	}

	wg.Wait()
}

// countMaliciousIssuesFromEvents queries the Events API for malicious package detection.
// Uses concurrent prefetching to batch sequential HTTP calls into parallel requests.
func countMaliciousIssuesFromEvents(serverId string, issueIDs []string) int {
	if len(issueIDs) == 0 {
		return 0
	}

	// First, prefetch all unique statuses concurrently (batches N sequential HTTP calls into parallel)
	prefetchMaliciousStatuses(serverId, issueIDs)

	// Then count cached results (fast — no more HTTP calls needed)
	count := 0
	for _, issueID := range issueIDs {
		maliciousCacheMutex.RLock()
		if maliciousCache[issueID] {
			count++
		}
		maliciousCacheMutex.RUnlock()
	}

	return count
}

func filterVulnerabilitiesBySeverity(vulnerabilities []services.Vulnerability, minSeverity string, serverId string) []services.Vulnerability {
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
			if isMaliciousWithCache(serverId, vuln.IssueId) {
				filtered = append(filtered, vuln)
			}
		} else if vulnLevel >= minLevel {
			filtered = append(filtered, vuln)
		}
	}

	return filtered
}

// generateSecurityBanner creates a visual banner based on the security status of findings
func generateSecurityBanner(serverId string, report *VulnerabilityReport, minSeverity string) {
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
		filteredVulns = filterVulnerabilitiesBySeverity(filteredVulns, minSeverity, serverId)
	}

	// Determine banner type based on filtered findings
	hasMalicious := false
	hasFindings := len(filteredVulns) > 0

	// Check for malicious content in filtered results
	for _, vuln := range filteredVulns {
		if isMaliciousWithCache(serverId, vuln.IssueId) {
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


func outputReport(serverId string, report *VulnerabilityReport, output string, minSeverity string, showFindings bool) error {
	switch output {
	case "json":
		return outputJSONReport(serverId, report)
	case "github-md":
		return outputMarkdownReport(serverId, report, minSeverity, showFindings)
	default:
		return fmt.Errorf("unsupported output format: %s. Use 'json' or 'github-md'", output)
	}
}

func outputJSONReport(serverId string, report *VulnerabilityReport) error {
	// Convert to enhanced format
	enhanced := convertToEnhancedReport(serverId, report)

	jsonData, err := json.MarshalIndent(enhanced, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(jsonData))
	return nil
}

func convertToEnhancedReport(serverId string, report *VulnerabilityReport) *EnhancedVulnerabilityReport {

	typeCount := make(map[string]int)
	issueIDs := collectUniqueIssueIDs(report)
	maliciousCount := countMaliciousIssuesFromEvents(serverId, issueIDs)

	var platforms []EnhancedPlatformInfo

	for _, platform := range report.Platforms {
		var findings []CompactFinding

		for _, vuln := range platform.Vulnerabilities {
			issueType := extractIssueType(vuln)
			if issueType == "" {
				issueType = "Security"
			}
			typeCount[issueType]++

			malicious := isMaliciousWithCache(serverId, vuln.IssueId)

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

func outputMarkdownReport(serverId string, report *VulnerabilityReport, minSeverity string, showFindings bool) error {
	// For GitHub MD output, suppress verbose logging and banners for silent operation
	silent := true

	fmt.Printf("# Xray Security Report: %s\n\n", report.ImageName)

	// Only generate banner if not in silent mode (for CI/CD pipelines)
	if !silent {
		generateSecurityBanner(serverId, report, minSeverity)
	}

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
	maliciousCount := countMaliciousIssuesFromEvents(serverId, issueIDs)

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

	if !silent {
		log.Info(fmt.Sprintf("📊 Malicious detection summary: Checked %d unique vulnerabilities, found %d malicious packages", len(vulnMap), maliciousCount))
	}

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
				filteredVulns = filterVulnerabilitiesBySeverity(filteredVulns, minSeverity, serverId)
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
					if isMaliciousWithCache(serverId, vuln.IssueId) {
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


func generateVulnerabilityReport(conf *CheckConfiguration, rtManager artifactory.ArtifactoryServicesManager, repoKey, imageName, tag string) (*VulnerabilityReport, error) {
	if !conf.Silent {
		log.Info(fmt.Sprintf("Generating vulnerability report for %s/%s:%s", repoKey, imageName, tag))
	}

	report := &VulnerabilityReport{
		ImageName:   fmt.Sprintf("%s/%s:%s", repoKey, imageName, tag),
		GeneratedAt: time.Now().Format(time.RFC3339),
		Platforms:   []PlatformVulnerabilityInfo{},
	}

	// Step 1: Dual-path discovery (handles both single-platform and multi-platform images)
	if !conf.Silent {
		log.Info("Running dual-path manifest discovery...")
	}
	platformPaths, err := discoverImageArtifacts(conf.ServerId, repoKey, imageName, tag)
	if err != nil {
		return nil, fmt.Errorf("manifest discovery failed: %w", err)
	}

	if len(platformPaths) == 0 {
		if !conf.Silent {
			log.Warn("No artifacts discovered — image may not be indexed in Xray or may use an unexpected path format")
		}
		return report, nil
	}

	if !conf.Silent {
		log.Info(fmt.Sprintf("Discovered %d artifact path(s) for vulnerabilities", len(platformPaths)))
	}

	// Step 2: Apply platform/OS filtering if specified
	if conf.Platform != "" || conf.OS != "" {
		arch := ""
		if conf.Platform != "" {
			parts := strings.SplitN(conf.Platform, "/", 2)
			if len(parts) == 2 {
				conf.OS = parts[0]
				arch = parts[1]
			} else {
				// --platform without slash: treat entire value as OS
				arch = conf.OS
				conf.OS = ""
			}
		}
		filtered := FilterManifestsByPlatform(platformPaths, arch, conf.OS)
		if len(filtered) == 0 {
			if !conf.Silent {
				log.Warn(fmt.Sprintf("No platforms match filter (arch=%q, os=%q)", arch, conf.OS))
			}
			return report, nil
		}
		platformPaths = filtered
		if !conf.Silent {
			log.Info(fmt.Sprintf("After platform/OS filtering: %d path(s) remaining", len(platformPaths)))
		}
	}

	// Step 3: Query vulnerabilities for each platform path
	vulnMap := make(map[string]services.Vulnerability)
	var successfulPath string
	totalVulnsAcrossPlatforms := 0

	for _, dp := range platformPaths {
		if !conf.Silent {
			log.Info(fmt.Sprintf("Querying Xray for: %s (digests: %v)", dp.path, dp.digests))
		}

		var vulns []services.Vulnerability
		var err error

		if len(dp.digests) > 0 {
			// Multi-platform or single-platform with digest — query by checksum (checksums now ignored, path is primary key for Violations API)
			vulns, err = getArtifactSummaryVulnerabilitiesCLI(conf.ServerId, conf.ProjectKey, dp.path)
		} else {
			// Single-platform without explicit digest — query by path only
			vulns, err = getArtifactSummaryVulnerabilitiesCLI(conf.ServerId, conf.ProjectKey, dp.path)
		}

		if err != nil {
			log.Debug(fmt.Sprintf("No data found for path: %s (error: %v)", dp.path, err))
			continue
		}

		if len(vulns) > 0 {
			beforeCount := len(vulnMap)
			for _, vuln := range vulns {
				if vuln.IssueId != "" {
					vulnMap[vuln.IssueId] = vuln
				}
			}
			newUnique := len(vulnMap) - beforeCount

			if successfulPath == "" {
				successfulPath = dp.path
			}

			log.Info(fmt.Sprintf("Found %d vulnerabilities at path: %s (new unique: %d)",
				len(vulns), dp.path, newUnique))

			// Build platform-specific vulnerability group
			platformInfo := PlatformVulnerabilityInfo{
				Vulnerabilities:  vulns,
				ManifestDigest:   dp.digests[0],
				Platform: Platform{
					OS:           dp.os,
					Architecture: dp.arch,
				},
			}

			report.Platforms = append(report.Platforms, platformInfo)
			totalVulnsAcrossPlatforms += len(vulns)
		}
	}

	// Step 4: Calculate summary counts from all platforms
	report.TotalIssues = totalVulnsAcrossPlatforms
	for _, platform := range report.Platforms {
		for _, vuln := range platform.Vulnerabilities {
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
	}

	if successfulPath != "" && !conf.Silent {
		log.Info(fmt.Sprintf("Successfully generated report with %d vulnerabilities from path: %s",
			totalVulnsAcrossPlatforms, successfulPath))
	} else if totalVulnsAcrossPlatforms == 0 {
		if !conf.Silent {
			log.Info("No vulnerabilities found for this image")
		}
	}

	return report, nil
}

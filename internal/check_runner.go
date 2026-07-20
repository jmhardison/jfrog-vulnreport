// Package internal implements the core logic for the jfrog-vulnreport plugin: orchestrating Docker
// manifest discovery, Xray vulnerability queries via the Violations API, and report formatting.
package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

// Constants for Docker media types recognized during manifest discovery.
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
		ImageName:          c.Arguments[0],
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
		WatchName:          c.GetStringFlagValue("watch-name"),
		MaliciousWatchName: c.GetStringFlagValue("malicious-watch-name"),
	}

	// Default project key to "default" if not specified.
	if conf.ProjectKey == "" {
		conf.ProjectKey = "default"
	}

	// watch-name is mandatory — users must explicitly choose which Xray watch's violations they want reported.
	if conf.WatchName == "" {
		return fmt.Errorf("--watch-name is required (e.g., dockerlocal-malicious-critical)")
	}
	if conf.MaliciousWatchName == "" {
		return fmt.Errorf("--malicious-watch-name is required — this watch defines which issue IDs are considered malicious")
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

	// Construct Artifactory URL and manifest path for linking from markdown output.
	// The manifest URL points to <artifactoryUrl>/<repo>/<image>/<tag>/manifest.json — users can click
	// this link in the github-md report to view their image directly in Artifactory's UI.
	serverDetails, err := getServerDetails(conf.ServerId)
	if err != nil {
		return fmt.Errorf("failed to get server configuration: %w", err)
	}

	// Generate vulnerability report (all Xray queries use CLI wrappers in internal/xray_cli.go).
	// The malicious lookup map is populated from the Violations API response, eliminating N+1 Events API calls.
	report, maliciousLookup, err := generateVulnerabilityReport(conf, serverDetails, repoKey, imageName, tag, conf.WatchName, conf.MaliciousWatchName)
	if err != nil {
		return fmt.Errorf("failed to generate vulnerability report: %w", err)
	}

	// Extract base platform URL and build manifest link path for github-md output.
	// The UI portal uses /ui/repos/tree/Xray/<repo>/<path> format, not the raw Artifactory URL.
	// Uses list.manifest.json for multi-platform images (shows all platforms), manifest.json for single-platform.
	baseUrl := strings.TrimRight(serverDetails.GetArtifactoryUrl(), "/")
	if idx := strings.Index(baseUrl, "/artifactory"); idx >= 0 {
		baseUrl = baseUrl[:idx] // Strip /artifactory to get base JFrog platform URL
	}
	manifestFilename := "manifest.json"
	if report.IsMultiPlatform {
		manifestFilename = "list.manifest.json"
	}
	manifestPath := fmt.Sprintf("%s/%s/%s/%s", repoKey, imageName, tag, manifestFilename)
	uiPortalManifestUrl := fmt.Sprintf("%s/ui/repos/tree/Xray/%s", baseUrl, manifestPath)

	// Output the report (passes uiPortalManifestUrl through for github-md links to JFrog Platform UI).
	if err := outputReport(report, maliciousLookup, conf.Output, uiPortalManifestUrl, conf.MinSeverity, conf.ShowFindings); err != nil {
		return fmt.Errorf("failed to output report: %w", err)
	}

	// Check if we should fail on vulnerabilities
	if conf.FailOnVuln && report.TotalIssues > 0 {
		return fmt.Errorf("found %d vulnerability issues", report.TotalIssues)
	}

	return nil
}

// Helper functions for enhanced report formatting

// extractIssueType classifies a vulnerability by its source (CVE, Malware, License, etc.) using the
// Technology field populated from the Violations API response. Falls back to issue ID pattern matching
// for legacy compatibility with older Xray data that may not include Technology.
func extractIssueType(vuln services.Vulnerability) string {
	// Use JFrog's official issue type classification stored in Technology field
	if vuln.Technology != "" {
		// Capitalize first letter for display (using strings.Title is acceptable here since we control the input)
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


// getSeverityIcon maps a severity name to its corresponding emoji indicator.
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

// getArtifactSummaryVulnerabilitiesCLI queries Xray Violations API using JFrog CLI subprocess to bypass JWT audience restrictions.
// Replaced SummaryService (/api/v1/summary/artifact) which hangs indefinitely for Docker images with Violations API (/api/v1/violations).
// Returns violations alongside their malicious_package status from the same response (no separate Events API calls needed).
// The watchName filter narrows results to those relevant to the user's JFrog Xray watch.
func getArtifactSummaryVulnerabilitiesCLI(serverId, projectKey, artifactPath, watchName string) ([]violationWithMalicious, error) {
	log.Info(fmt.Sprintf("Querying Xray Violations API via CLI for path: %s (project: %s, watch: %s)", artifactPath, projectKey, watchName))

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
		return nil, fmt.Errorf("failed to query Xray Violations API via CLI: %w", err)
	}

	log.Info(fmt.Sprintf("Extracted %d violations from Violations API response (malicious status included)", len(results)))
	return results, nil
}


// filterVulnerabilitiesBySeverity filters a vulnerability list by minimum severity threshold.
// When minSeverity is "Malicious", uses the pre-built lookup map (no Events API calls needed).
func filterVulnerabilitiesBySeverity(vulnerabilities []services.Vulnerability, minSeverity string, maliciousLookup map[string]bool) []services.Vulnerability {
	if minSeverity == "" {
		return vulnerabilities
	}

	severityOrder := map[string]int{
		"Low":       1,
		"Medium":    2,
		"High":      3,
		"Critical":  4,
		"Malicious": 5, // Highest severity level — only includes findings flagged malicious in Violations API
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

		// Special case: if filtering for "Malicious", only show malicious content.
		// Uses pre-built lookup map (no Events API calls needed).
		if minSeverity == "Malicious" {
			if maliciousLookup[vuln.IssueId] {
				filtered = append(filtered, vuln)
			}
		} else if vulnLevel >= minLevel {
			filtered = append(filtered, vuln)
		}
	}

	return filtered
}

// generateSecurityBanner renders a GitHub-flavored alert banner (CAUTION/WARNING/NOTE) based on whether
// the report contains malicious packages or any vulnerabilities. Uses pre-built lookup map for malicious
// detection — no Events API calls needed during output formatting.
func generateSecurityBanner(report *VulnerabilityReport, maliciousLookup map[string]bool, minSeverity string) {
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

	// Apply the same filtering logic used for display (uses pre-built malicious lookup instead of Events API).
	filteredVulns := allVulns
	if minSeverity != "" {
		filteredVulns = filterVulnerabilitiesBySeverity(filteredVulns, minSeverity, maliciousLookup)
	}

	// Determine banner type based on filtered findings
	hasMalicious := false
	hasFindings := len(filteredVulns) > 0

	// Check for malicious content in filtered results using pre-built lookup (no HTTP calls).
	for _, vuln := range filteredVulns {
		if maliciousLookup[vuln.IssueId] {
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


// outputReport dispatches to the appropriate formatter based on the requested output format.
// manifestUrl is used by github-md output to render a clickable link to the image's manifest in JFrog Platform UI —
// no additional API calls needed, just URL construction from server config.
func outputReport(report *VulnerabilityReport, maliciousLookup map[string]bool, output string, manifestUrl string, minSeverity string, showFindings bool) error {
	switch output {
	case "json":
		return outputJSONReport(report, maliciousLookup)
	case "github-md":
		return outputMarkdownReport(report, maliciousLookup, manifestUrl, minSeverity, showFindings)
	default:
		return fmt.Errorf("unsupported output format: %s. Use 'json' or 'github-md'", output)
	}
}

// outputJSONReport converts the VulnerabilityReport to an EnhancedVulnerabilityReport (with per-finding
// malicious status and issue type counts), then prints it as indented JSON to stdout.
func outputJSONReport(report *VulnerabilityReport, maliciousLookup map[string]bool) error {
	// Convert to enhanced format using pre-built malicious lookup (no Events API calls needed).
	enhanced := convertToEnhancedReport(report, maliciousLookup)

	jsonData, err := json.MarshalIndent(enhanced, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(jsonData))
	return nil
}

// convertToEnhancedReport flattens the per-platform VulnerabilityReport into a single aggregated view.
// The malicious lookup map (built from Violations API response) is used to annotate each finding with
// its malicious status — no additional HTTP requests needed.
func convertToEnhancedReport(report *VulnerabilityReport, maliciousLookup map[string]bool) *EnhancedVulnerabilityReport {

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

			malicious := maliciousLookup[vuln.IssueId]
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

	// Add orphaned malicious findings (detected via malicious watch but not as regular violations).
	var findings []CompactFinding
	for _, p := range platforms {
		findings = append(findings, p.Findings...)
	}

	for _, issueID := range report.OrphanedMalicious {
		finding := CompactFinding{
			IssueId:   issueID,
			Type:      "Security",
			Severity:  "Critical", // Malicious is Critical severity
			Malicious: true,
			CveCount:  0,
		}
		findings = append(findings, finding)
		if _, exists := typeCount["Security"]; !exists {
			typeCount["Security"] = 1
		} else {
			typeCount["Security"]++
		}
		maliciousCount++

		enhancedPlatform := EnhancedPlatformInfo{
			Platform:      report.Platforms[0].Platform, // Inherit platform info from first platform
			FindingsCount: 1,
			LayerCount:    0,
			SizeMB:        0,
			Findings:      []CompactFinding{finding},
		}
		platforms = append(platforms, enhancedPlatform)
	}

	return &EnhancedVulnerabilityReport{
		ImageName:   report.ImageName,
		GeneratedAt: report.GeneratedAt,
		Summary: SecuritySummary{
			TotalFindings:  report.TotalIssues + len(report.OrphanedMalicious),
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

// isOrphaned checks whether an issue ID was found in the malicious-only watch but not returned as a violation.
func isOrphaned(orphanedMalicious []string, issueID string) bool {
	for _, id := range orphanedMalicious {
		if id == issueID {
			return true
		}
	}
	return false
}

// outputMarkdownReport generates a GitHub-flavored markdown security report. Uses the pre-built malicious
// lookup map (no Events API calls) for per-finding malicious status and summary counts. The manifestUrl
// parameter is used to render a clickable link to the image's manifest in JFrog Platform UI —
// constructed as <baseUrl>/ui/repos/tree/General/<repo>/<path>/list.manifest.json without additional HTTP requests.
func outputMarkdownReport(report *VulnerabilityReport, maliciousLookup map[string]bool, manifestUrl string, minSeverity string, showFindings bool) error {
	// For GitHub MD output, suppress verbose logging and banners for silent operation
	silent := true

	fmt.Printf("# Xray Security Report\n\n")
	fmt.Printf("## %s\n\n", report.ImageName)

	// Render a clickable link to the image's manifest in JFrog Platform UI so users can view their image directly.
	// The URL is pre-constructed from server config — no additional API calls needed.
	if manifestUrl != "" {
		fmt.Printf("> **View manifest:** [%s](%s)\n\n", report.ImageName, manifestUrl)
	}

	fmt.Println()

	// Only generate banner if not in silent mode (for CI/CD pipelines)
	if !silent {
		generateSecurityBanner(report, maliciousLookup, minSeverity)
	}

	// Security Summary with counts
	fmt.Println("## Security Summary")

	// Deduplicate vulnerabilities across all platforms for accurate counting and display
	vulnMap := make(map[string]services.Vulnerability)

	for _, platform := range report.Platforms {
		for _, vuln := range platform.Vulnerabilities {
			// Use Xray ID as key to ensure each unique vulnerability is counted only once
			if vuln.IssueId != "" {
				vulnMap[vuln.IssueId] = vuln
			}
		}
	}

	maliciousCount := 0
	for issueID, malicious := range maliciousLookup {
		if _, exists := vulnMap[issueID]; exists && malicious {
			maliciousCount++
		}
	}

	typeCount := make(map[string]int)

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
	maliciousCount += len(report.OrphanedMalicious)
	fmt.Printf("- **Malicious:** %d\n", maliciousCount)
	fmt.Printf("- **Platforms Scanned:** %d\n", len(report.Platforms))
	if len(report.Platforms) > 0 {
		var platformList []string
		for _, p := range report.Platforms {
			platformList = append(platformList, fmt.Sprintf("%s/%s", p.Platform.OS, p.Platform.Architecture))
		}
		fmt.Printf("- **Platforms:** %s\n\n", strings.Join(platformList, ", "))
	} else {
		fmt.Println()
	}

	// Break out malicious findings into a dedicated section at the top.
	totalMaliciousCount := maliciousCount
	if totalMaliciousCount > 0 && len(vulnMap) > 0 {
		fmt.Println()
		fmt.Println("---")
		fmt.Println()
		// Collect regular malicious findings (present in both the report watch AND malicious-only watch).
		maliciousVulns := make(map[string]services.Vulnerability)
		for issueID, malicious := range maliciousLookup {
			if vuln, exists := vulnMap[issueID]; exists && malicious {
				maliciousVulns[issueID] = vuln
			}
		}
		fmt.Printf("## :bangbang: Malicious Findings (%d)\n", totalMaliciousCount)
		fmt.Println("| Xray ID | Severity |")
		fmt.Println("|---------|----------|")
		type sortedItem struct {
			id   string
			vuln services.Vulnerability
		}
		var items []sortedItem
		for id, vuln := range maliciousVulns {
			items = append(items, sortedItem{id, vuln})
		}
		// Also include orphans (only in malicious-only watch, not in report watch)
		for _, oid := range report.OrphanedMalicious {
			items = append(items, sortedItem{id: oid, vuln: services.Vulnerability{}})
		}
		for i := 0; i < len(items); i++ {
			for j := i + 1; j < len(items); j++ {
				if items[i].id > items[j].id {
					items[i], items[j] = items[j], items[i]
				}
			}
		}
		for _, it := range items {
			if isOrphaned(report.OrphanedMalicious, it.id) {
				fmt.Printf("| %s | Malicious (detected via malicious-only watch) |\n", it.id)
			} else {
				fmt.Printf("| %s | Malicious |\n", it.id)
			}
		}
		fmt.Println()
		fmt.Println("---")
		fmt.Println()
	}
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
				filteredVulns = filterVulnerabilitiesBySeverity(filteredVulns, minSeverity, maliciousLookup)
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
				fmt.Println("| Xray ID | Type | Severity |")
				fmt.Println("|---------|------|----------|")

				for _, vuln := range filteredVulns {
					issueType := extractIssueType(vuln)
					if issueType == "" {
						issueType = "Security"
					}

					severityIcon := getSeverityIcon(vuln.Severity)

					fmt.Printf("| %s | %s | %s %s |\n",
					vuln.IssueId,
					issueType,
					severityIcon,
					vuln.Severity)
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

// parseImageName splits a full image reference (e.g., "docker-local/myimage:latest") into its
// repository key, image name, and tag components. Used as the first step in artifact discovery.
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


// generateVulnerabilityReport orchestrates the full vulnerability query pipeline:
//  1. Discovers artifact paths via Artifactory search (handles both single and multi-platform images)
//  2. Queries Xray Violations API for each platform path, scoped to watch_name
//  3. Builds a malicious lookup map from Violations response data
//  4. Aggregates vulnerability counts across all platforms
//
// The watchName filter narrows violations to those relevant to the user's JFrog Xray watch — without it,
// the API returns all violations in the project (potentially thousands of unrelated results).
// The maliciousLookup map is populated from the Violations API response (not Events API), eliminating
// N+1 HTTP requests. It maps issue ID → whether it's a malicious package, and is passed to output
// functions for use in report generation.
func generateVulnerabilityReport(conf *CheckConfiguration, serverDetails *config.ServerDetails, repoKey, imageName, tag, watchName, maliciousWatchName string) (*VulnerabilityReport, map[string]bool, error) {
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
	platformPaths, err := discoverImageArtifacts(conf.ServerId, serverDetails, repoKey, imageName, tag)
	if err != nil {
		return nil, nil, fmt.Errorf("manifest discovery failed: %w", err)
	}

	if len(platformPaths) == 0 {
		if !conf.Silent {
			log.Warn("No artifacts discovered — image may not be indexed in Xray or may use an unexpected path format")
		}
		return report, map[string]bool{}, nil
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
			return report, map[string]bool{}, nil
		}
		platformPaths = filtered
		if !conf.Silent {
			log.Info(fmt.Sprintf("After platform/OS filtering: %d path(s) remaining", len(platformPaths)))
		}
	}

	// Step 2a: Phase 1 — Query the malicious-only watch to resolve issue IDs that count as malicious.
	// The Violations API's own malicious_package field is unreliable, so we always use a dedicated
	// --malicious-watch-name as the source of truth.
	maliciousLookup := make(map[string]bool)

	log.Info(fmt.Sprintf("Resolving malicious issue IDs from watch: %s", conf.MaliciousWatchName))

	for _, dp := range platformPaths {
		maliciousResults, err := getArtifactSummaryVulnerabilitiesCLI(conf.ServerId, conf.ProjectKey, dp.path, conf.MaliciousWatchName)
		if err != nil {
			log.Debug(fmt.Sprintf("Malicious watch query returned error for path %s: %v", dp.path, err))
			continue
		}
		for _, r := range maliciousResults {
			if r.Vulnerability.IssueId != "" {
				maliciousLookup[r.Vulnerability.IssueId] = true
			}
		}
		log.Debug(fmt.Sprintf("Malicious watch query for path %s returned %d violation(s)", dp.path, len(maliciousResults)))
	}

		// Step 3: Query vulnerabilities for each platform path
	vulnMap := make(map[string]services.Vulnerability)
	var successfulPath string

	// Try each Docker path format until we get vulnerability data
	for _, path := range dockerPaths {
		if !conf.Silent {
			log.Info(fmt.Sprintf("Querying Xray for: %s (digests: %v)", dp.path, dp.digests))
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
		}

		if len(results) > 0 {
			newUnique := len(vulnMap) - beforeCount

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

		platformInfo := PlatformVulnerabilityInfo{
			Vulnerabilities:  vulns,
			ManifestDigest:   dp.digests[0],
			Platform: Platform{
				OS:           dp.os,
				Architecture: dp.arch,
			},
		}

		if dp.isList {
			report.IsMultiPlatform = true // Remember this was a multi-platform image for manifest URL construction
		}
		report.Platforms = append(report.Platforms, platformInfo)
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
				len(allVulns), successfulPath))
		}
	} else {
		if !conf.Silent {
			log.Info("No vulnerabilities found for this image")
		}
	}

	// Compute orphaned malicious IDs: found in malicious watch but not in any report watch violation.
	if len(maliciousLookup) > 0 {
		orphanedMalicious := make([]string, 0)
		for issueID := range maliciousLookup {
			if _, exists := vulnMap[issueID]; !exists {
				orphanedMalicious = append(orphanedMalicious, issueID)
			}
		}
		if len(orphanedMalicious) > 0 {
			log.Info(fmt.Sprintf("Found %d malicious issue(s) not returned by report watch (only in malicious-only watch): %v", len(orphanedMalicious), orphanedMalicious))
		}
		report.OrphanedMalicious = orphanedMalicious
	}

	return report, maliciousLookup, nil
}

// Package internal implements the core logic for the jfrog-vulnreport plugin: orchestrating Docker
// manifest discovery, Xray vulnerability queries via the Violations API, and report formatting.
package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jfrog/jfrog-cli-core/v2/plugins/common"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	configCore "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	configBuilder "github.com/jfrog/jfrog-client-go/config"
	"github.com/jfrog/jfrog-client-go/http/jfroghttpclient"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xraySdk "github.com/jfrog/jfrog-client-go/xray"
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
		DebugPaths:        c.GetBoolFlagValue("debug-paths"),
		DockerRegistryURL: c.GetStringFlagValue("docker-registry-url"),
		ProjectKey:        c.GetStringFlagValue("project-key"),
		MaliciousWatchName: c.GetStringFlagValue("malicious-watch-name"),
	}

	// Default project key to "default" if not specified.
	if conf.ProjectKey == "" {
		conf.ProjectKey = "default"
	}

	if conf.MaliciousWatchName == "" {
		return fmt.Errorf("--malicious-watch-name is required — this watch defines which issue IDs are considered malicious")
	}

	// Parse image name to extract repository and tag
	repoKey, imageName, tag, err := ParseImageName(conf.ImageName)
	if err != nil {
		return fmt.Errorf("invalid image format: %w", err)
	}

	serverDetails, err := getServerDetails(c)
	if err != nil {
		return fmt.Errorf("failed to get server configuration: %w", err)
	}

	xraySvc, err := newXrayService(serverDetails)
	if err != nil {
		return fmt.Errorf("failed to create Xray service: %w", err)
	}
	log.Info(fmt.Sprintf("[XrayService] URL=%s", xraySvc.XrayDetails.GetUrl()))
	artSvc, err := newArtifactoryService(serverDetails)
	if err != nil {
		return fmt.Errorf("failed to create Artifactory service: %w", err)
	}

	// Build JFrog Platform base URL for UI links (strips /artifactory suffix if present).
	artifactoryBaseURL := strings.TrimRight(serverDetails.GetArtifactoryUrl(), "/")
	if idx := strings.Index(artifactoryBaseURL, "/artifactory"); idx >= 0 {
		artifactoryBaseURL = artifactoryBaseURL[:idx]
	}

	return RunCheckCommandFromConf(conf, repoKey, imageName, tag, artifactoryBaseURL, xraySvc, artSvc)
}

// RunCheckCommandFromConf runs the check pipeline with pre-built, authenticated services.
// Used by RunCheckCommand (normal CLI path) and by Exec() when services are injected for testing.
// artifactoryBaseURL is the JFrog Platform base URL (e.g. "https://company.jfrog.io") used to
// build UI links; pass empty string to omit link generation.
func RunCheckCommandFromConf(conf *CheckConfiguration, repoKey, imageName, tag, artifactoryBaseURL string, xraySvc *XrayService, artSvc *ArtifactoryService) error {
	if conf.Silent {
		log.SetLogger(log.NewLogger(log.ERROR, os.Stderr))
	}
	if !conf.Silent {
		log.Info(fmt.Sprintf("Checking vulnerabilities for image: %s/%s:%s", repoKey, imageName, tag))
	}

	report, maliciousLookup, err := generateVulnerabilityReport(conf, repoKey, imageName, tag, xraySvc, artSvc)
	if err != nil {
		return fmt.Errorf("failed to generate vulnerability report: %w", err)
	}

	// Build UI portal manifest link (list.manifest.json for multi-platform, manifest.json otherwise).
	manifestFilename := "manifest.json"
	if report.IsMultiPlatform {
		manifestFilename = "list.manifest.json"
	}
	var uiPortalManifestUrl string
	if artifactoryBaseURL != "" {
		manifestPath := fmt.Sprintf("%s/%s/%s/%s", repoKey, imageName, tag, manifestFilename)
		uiPortalManifestUrl = fmt.Sprintf("%s/ui/repos/tree/Xray/%s", artifactoryBaseURL, manifestPath)
	}

	if err := outputReport(report, maliciousLookup, conf.Output, uiPortalManifestUrl, conf.MinSeverity); err != nil {
		return fmt.Errorf("failed to output report: %w", err)
	}

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


// generateSecurityBanner renders a GitHub-flavored alert banner (CAUTION/WARNING/NOTE) based on whether
// the report contains malicious packages or any vulnerabilities.
func generateSecurityBanner(report *VulnerabilityReport, maliciousLookup map[string]bool, minSeverity string) {
	hasMalicious := len(maliciousLookup) > 0 || len(report.MaliciousIssues) > 0
	hasFindings := report.TotalIssues > 0

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
func outputReport(report *VulnerabilityReport, maliciousLookup map[string]bool, output string, manifestUrl string, minSeverity string) error {
	switch output {
	case "json":
		return outputJSONReport(report, maliciousLookup)
	case "github-md":
		return outputMarkdownReport(report, maliciousLookup, manifestUrl, minSeverity)
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
			MaliciousCount: len(maliciousLookup),
			PlatformCount:  len(report.Platforms),
		},
		IssueTypes: typeCount,
		Platforms:  platforms,
	}
}

// outputMarkdownReport generates a GitHub-flavored markdown security report. Uses the pre-built malicious
// lookup map (no Events API calls) for per-finding malicious status and summary counts. The manifestUrl
// parameter is used to render a clickable link to the image's manifest in JFrog Platform UI —
// constructed as <baseUrl>/ui/repos/tree/General/<repo>/<path>/list.manifest.json without additional HTTP requests.
func outputMarkdownReport(report *VulnerabilityReport, maliciousLookup map[string]bool, manifestUrl string, minSeverity string) error {
	fmt.Printf("# Xray Security Report\n\n")
	fmt.Printf("## %s\n\n", report.ImageName)

	if manifestUrl != "" {
		fmt.Printf("> **View manifest:** [%s](%s)\n\n", report.ImageName, manifestUrl)
	}

	fmt.Println()

	generateSecurityBanner(report, maliciousLookup, minSeverity)

	fmt.Println("## Security Summary")

	maliciousCount := len(report.MaliciousIssues)
	fmt.Printf("- **Total Findings:** %d\n", report.TotalIssues)
	fmt.Printf("- **Critical:** %d | **High:** %d | **Medium:** %d | **Low:** %d\n",
		report.CriticalCount, report.HighCount, report.MediumCount, report.LowCount)
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

	if maliciousCount > 0 {
		fmt.Println()
		fmt.Println("---")
		fmt.Println()
		fmt.Printf("## :bangbang: Malicious Findings (%d)\n", maliciousCount)
		fmt.Println("| Xray ID | Severity |")
		fmt.Println("|---------|----------|")
		sorted := make([]string, len(report.MaliciousIssues))
		copy(sorted, report.MaliciousIssues)
		for i := 0; i < len(sorted); i++ {
			for j := i + 1; j < len(sorted); j++ {
				if sorted[i] > sorted[j] {
					sorted[i], sorted[j] = sorted[j], sorted[i]
				}
			}
		}
		for _, id := range sorted {
			fmt.Printf("| %s | Malicious |\n", id)
		}
		fmt.Println()
		fmt.Println("---")
		fmt.Println()
	}

	return nil
}

// Missing functions - minimal implementations

// ParseImageName splits a full image reference (e.g., "docker-local/myimage:latest") into its
// repository key, image name, and tag components. Used as the first step in artifact discovery.
func ParseImageName(imageName string) (string, string, string, error) {
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

// getServerDetails retrieves authenticated server details from the jfrog CLI framework.
// This ensures JWT tokens are properly initialized via CreateInitialRefreshableTokensIfNeeded,
// which is required for direct SDK client calls (not just CLI subprocesses).
func getServerDetails(c *components.Context) (*configCore.ServerDetails, error) {
	return common.GetServerDetails(c)
}

// newXrayService creates an XrayService from server details using the platform access token.
// common.GetServerDetails already calls CreateInitialRefreshableTokensIfNeeded so the token
// in serverDetails is ready for direct SDK use.
func newXrayService(serverDetails *configCore.ServerDetails) (*XrayService, error) {
	xrayDetails, err := serverDetails.CreateXrayAuthConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create Xray auth config: %w", err)
	}

	cfg, err := configBuilder.NewConfigBuilder().SetServiceDetails(xrayDetails).Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build Xray config: %w", err)
	}

	xrayMgr, err := xraySdk.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Xray manager: %w", err)
	}

	return NewXrayService(xrayMgr.Client(), xrayDetails), nil
}

// newArtifactoryService creates an ArtifactoryService from server details.
// Mirrors newXrayService — builds an authenticated JfrogHttpClient using CreateArtAuthConfig.
func newArtifactoryService(serverDetails *configCore.ServerDetails) (*ArtifactoryService, error) {
	artDetails, err := serverDetails.CreateArtAuthConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create Artifactory auth config: %w", err)
	}

	client, err := jfroghttpclient.JfrogClientBuilder().
		SetClientCertPath(artDetails.GetClientCertPath()).
		SetClientCertKeyPath(artDetails.GetClientCertKeyPath()).
		AppendPreRequestInterceptor(artDetails.RunPreRequestFunctions).
		Build()
	if err != nil {
		return nil, fmt.Errorf("failed to create Artifactory HTTP client: %w", err)
	}

	return NewArtifactoryService(client, artDetails), nil
}

// generateVulnerabilityReport orchestrates the full vulnerability query pipeline:
//  1. Discovers artifact paths via Artifactory search (handles both single and multi-platform images)
//  2. Queries the malicious watch to build a lookup map of known malicious issue IDs
//  3. Calls the Xray summary API to get total/severity counts (not watch-scoped)
//
// The maliciousLookup map maps issue ID → true for every issue ID returned by the malicious watch.
// Summary counts are used for the Security Summary section in both JSON and markdown output.
func generateVulnerabilityReport(conf *CheckConfiguration, repoKey, imageName, tag string, xraySvc *XrayService, artSvc *ArtifactoryService) (*VulnerabilityReport, map[string]bool, error) {
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
	platformPaths, err := discoverImageArtifacts(artSvc, repoKey, imageName, tag)
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
				conf.OS = conf.Platform
				arch = ""
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

	// Initialize lastDp from the last discovered path to carry platform metadata into the report.
	var lastDp dockerPath
	if len(platformPaths) > 0 {
		lastDp = platformPaths[len(platformPaths)-1]
	}
	if lastDp.isList {
		report.IsMultiPlatform = true
	}

	// Step 2a: Query the malicious-only watch to resolve issue IDs that count as malicious.
	// The Violations API's own malicious_package field is unreliable, so we always use a dedicated
	// --malicious-watch-name as the source of truth. Uses SDK-based XrayService (Phase 4).
	maliciousLookup := make(map[string]bool)

	log.Info(fmt.Sprintf("Resolving malicious issue IDs from watch: %s", conf.MaliciousWatchName))

	for _, dp := range platformPaths {
		maliciousResults, err := xraySvc.GetViolations(conf.MaliciousWatchName, extractRepoFromPath(dp.path), dp.path, conf.ProjectKey)
		if err != nil {
			log.Warn(fmt.Sprintf("Malicious watch query returned error for path %s: %v", dp.path, err))
			continue
		}
		for _, r := range maliciousResults {
			if r.Vulnerability.IssueId != "" {
				maliciousLookup[r.Vulnerability.IssueId] = true
			}
		}
		log.Debug(fmt.Sprintf("Malicious watch query for path %s returned %d violation(s)", dp.path, len(maliciousResults)))
	}

	// Collect artifact checksums for the summary API. Strip "sha256:" prefix: single-platform
	// digests from AQL are raw hex; multi-platform digests from list.manifest.json have the prefix.
	var summaryChecksums []string
	seenChecksums := make(map[string]bool)
	for _, dp := range platformPaths {
		for _, digest := range dp.digests {
			hex := strings.TrimPrefix(digest, "sha256:")
			if hex != "" && !seenChecksums[hex] {
				seenChecksums[hex] = true
				summaryChecksums = append(summaryChecksums, hex)
			}
		}
	}

	// Get severity counts from summary API (not watch-scoped — returns all vulnerabilities
	// Xray knows about regardless of watch policy). Sets the report severity counts used by
	// the Security Summary section in both JSON and markdown output.
	// Note: this call can take 30-90s for large images; we time out after summaryTimeout
	// and fall back to violations-based counts.
	log.Info(fmt.Sprintf("Fetching vulnerability summary from Xray for %d artifact checksum(s)...", len(summaryChecksums)))
	summaryCounts, summaryErr := xraySvc.GetSummaryByChecksums(summaryChecksums)
	if summaryErr != nil {
		log.Warn(fmt.Sprintf("Summary API: %v — falling back to violations-based counts", summaryErr))
		// Fallback: query violations with no watch filter to get counts for all watched violations.
		// This is incomplete compared to the summary API (misses unwatched vulnerabilities) but is
		// fast and returns a meaningful count instead of zero.
		fallbackVulnMap := make(map[string]services.Vulnerability)
		for _, dp := range platformPaths {
			vv, err := xraySvc.GetViolations("", extractRepoFromPath(dp.path), dp.path, conf.ProjectKey)
			if err != nil {
				log.Warn(fmt.Sprintf("Fallback violations query failed for %s: %v", dp.path, err))
				continue
			}
			for _, v := range vv {
				if v.Vulnerability.IssueId != "" {
					fallbackVulnMap[v.Vulnerability.IssueId] = v.Vulnerability
				}
			}
		}
		report.TotalIssues = len(fallbackVulnMap)
		for _, vuln := range fallbackVulnMap {
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
	} else {
		report.TotalIssues = summaryCounts.Total
		report.CriticalCount = summaryCounts.Critical
		report.HighCount = summaryCounts.High
		report.MediumCount = summaryCounts.Medium
		report.LowCount = summaryCounts.Low
	}

	var manifestDigest string
	if len(lastDp.digests) > 0 {
		manifestDigest = lastDp.digests[0]
	}
	platformInfo := PlatformVulnerabilityInfo{
		ManifestDigest: manifestDigest,
		Platform: Platform{
			OS:           lastDp.os,
			Architecture: lastDp.arch,
		},
	}
	report.Platforms = append(report.Platforms, platformInfo)

	for issueID := range maliciousLookup {
		report.MaliciousIssues = append(report.MaliciousIssues, issueID)
	}

	return report, maliciousLookup, nil
}

// Package internal implements the core logic for the jfrog-vulnreport plugin: orchestrating Docker
// manifest discovery, Xray vulnerability queries via the Violations API, and report formatting.
package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jfrog/jfrog-cli-core/v2/plugins/common"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	configCore "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	configBuilder "github.com/jfrog/jfrog-client-go/config"
	"github.com/jfrog/jfrog-client-go/http/jfroghttpclient"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xraySdk "github.com/jfrog/jfrog-client-go/xray"
)

// Constants for Docker media types recognized during manifest discovery.
const (
	MediaTypeManifest     = "application/vnd.docker.distribution.manifest.v2+json"
	MediaTypeManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
	MediaTypeOCIManifest  = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeOCIIndex     = "application/vnd.oci.image.index.v1+json"
)

func RunCheckCommand(c *components.Context, appName, appVersion string) error {
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
		ServerId:           c.GetStringFlagValue("server-id"),
		Platform:           c.GetStringFlagValue("platform"),
		FailOnVuln:         c.GetBoolFlagValue("fail-on-vuln"),
		Output:             output,
		Silent:             output == "github-md",
		MinSeverity:        c.GetStringFlagValue("min-severity"),
		DebugPaths:         c.GetBoolFlagValue("debug-paths"),
		DockerRegistryURL:  c.GetStringFlagValue("docker-registry-url"),
		ProjectKey:         c.GetStringFlagValue("project-key"),
		MaliciousWatchName: c.GetStringFlagValue("malicious-watch-name"),
		NoFindings:         c.GetBoolFlagValue("no-findings"),
		AppName:            appName,
		AppVersion:         appVersion,
	}

	// Default project key to "default" if not specified.
	if conf.ProjectKey == "" {
		conf.ProjectKey = "default"
	}

	if conf.Silent {
		log.SetLogger(log.NewLogger(log.ERROR, os.Stderr))
	}

	if conf.MaliciousWatchName == "" {
		return fmt.Errorf("--malicious-watch-name is required — this watch defines which issue IDs are considered malicious")
	}

	// Parse image name to extract repository and tag
	repoKey, imageName, tag, err := ParseImageName(conf.ImageName, c.GetStringFlagValue("repo"))
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

	if err := outputReport(report, maliciousLookup, conf.Output, uiPortalManifestUrl, conf.MinSeverity, conf.NoFindings, conf.AppName, conf.AppVersion); err != nil {
		return fmt.Errorf("failed to output report: %w", err)
	}

	if conf.FailOnVuln && report.TotalIssues > 0 {
		return fmt.Errorf("found %d vulnerability issues", report.TotalIssues)
	}

	return nil
}

// generateSecurityBanner renders a GitHub-flavored alert banner based on the highest-severity finding tier:
//   - Malicious detected → [!CAUTION] red banner (always takes priority)
//   - Critical CVEs, no malicious → [!CAUTION] orange banner
//   - Non-critical CVEs, no malicious → [!WARNING] yellow banner
//   - No findings → [!NOTE] green banner
func generateSecurityBanner(report *VulnerabilityReport, maliciousLookup map[string]bool) {
	hasMalicious := len(maliciousLookup) > 0 || len(report.MaliciousIssues) > 0
	hasCritical := report.CriticalCount > 0
	hasFindings := report.TotalIssues > 0

	switch {
	case hasMalicious:
		// RED banner for malicious content
		fmt.Println("![Malicious](https://raw.githubusercontent.com/jmhardison/jfrog-vulnreport/main/images/badge-malicious.png)")
		fmt.Println("---")
		fmt.Println()
		fmt.Println("> [!CAUTION]")
		fmt.Println("> ## :rotating_light: MALICIOUS EXPLOIT PRESENT :rotating_light:")
		fmt.Println("> **IMMEDIATE ACTION REQUIRED** - Malicious content detected in this image. Remediate or seek guidance.")
		fmt.Println("> Policies can prevent the download and execution of this image, resulting in potential deploy issues such as `imagePullBackoff`.")
		fmt.Println("> Do `not` promote until confirmed, and stop use of image if not a false positive.")
		fmt.Println()
		fmt.Println()
		fmt.Println("---")
		fmt.Println()
	case hasCritical:
		// ORANGE banner for critical CVEs (no malicious)
		fmt.Println("![Critical CVEs](https://raw.githubusercontent.com/jmhardison/jfrog-vulnreport/main/images/badge-critical-cve.png)")
		fmt.Println("---")
		fmt.Println()
		fmt.Println("> [!CAUTION]")
		fmt.Println("> ## :red_circle: CRITICAL CVE'S PRESENT")
		fmt.Println("> Critical severity vulnerabilities found - review and remediation required.")
		fmt.Println("> Fixable critical issues should be resolved before promotion.")
		fmt.Println()
		fmt.Println()
		fmt.Println("---")
		fmt.Println()
	case hasFindings:
		// YELLOW banner for non-critical CVEs present
		fmt.Println("![CVEs Present](https://raw.githubusercontent.com/jmhardison/jfrog-vulnreport/main/images/badge-cves-present.png)")
		fmt.Println("---")
		fmt.Println()
		fmt.Println("> [!WARNING]")
		fmt.Println("> ## :warning: CVE's PRESENT")
		fmt.Println("> Security vulnerabilities found - review and remediate as needed")
		fmt.Println("> Promotion won't be blocked, however fixable issues should be resolved before promotion when possible.")
		fmt.Println()
		fmt.Println()
		fmt.Println("---")
		fmt.Println()
	default:
		// GREEN banner for clean image
		fmt.Println("![No Findings](https://raw.githubusercontent.com/jmhardison/jfrog-vulnreport/main/images/badge-no-findings.png)")
		fmt.Println("---")
		fmt.Println()
		fmt.Println("> [!NOTE]")
		fmt.Println("> ## :white_check_mark: NO FINDINGS")
		fmt.Println("> No security issues found - image appears clean")
		fmt.Println()
		fmt.Println()
		fmt.Println("---")
		fmt.Println()
	}
}

// outputReport dispatches to the appropriate formatter based on the requested output format.
// manifestUrl is used by github-md output to render a clickable link to the image's manifest in JFrog Platform UI —
// no additional API calls needed, just URL construction from server config.
func outputReport(report *VulnerabilityReport, maliciousLookup map[string]bool, output string, manifestUrl string, minSeverity string, noFindings bool, appName, appVersion string) error {
	switch output {
	case "json":
		return outputJSONReport(report, maliciousLookup)
	case "github-md":
		return outputMarkdownReport(report, maliciousLookup, manifestUrl, minSeverity, noFindings, appName, appVersion)
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
		enhancedPlatform := EnhancedPlatformInfo{
			Platform:      platform.Platform,
			FindingsCount: 0,
			LayerCount:    platform.LayerCount,
			SizeMB:        float64(platform.TotalSize) / (1024 * 1024),
			Findings:      nil,
		}
		platforms = append(platforms, enhancedPlatform)
	}

	return &EnhancedVulnerabilityReport{
		ImageName:     report.ImageName,
		GeneratedAt:   report.GeneratedAt,
		ImageNotFound: report.ImageNotFound,
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
func outputMarkdownReport(report *VulnerabilityReport, maliciousLookup map[string]bool, manifestUrl string, minSeverity string, noFindings bool, appName, appVersion string) error {
	if report.ImageNotFound {
		fmt.Println("![No Image Found](https://raw.githubusercontent.com/jmhardison/jfrog-vulnreport/main/images/badge-no-image-found.png)")
		fmt.Println("---")
		fmt.Println()
		fmt.Printf("# Xray Security Report\n\n")
		fmt.Printf("## %s\n\n", report.ImageName)
		fmt.Println("No Image Found - Check the image name/tag, or that publishing is complete.")
		fmt.Println()
		fmt.Printf("> Generated by %s %s\n", appName, appVersion)
		fmt.Println()
		return nil
	}

	generateSecurityBanner(report, maliciousLookup)

	fmt.Printf("# Xray Security Report\n\n")
	fmt.Printf("## %s\n\n", report.ImageName)

	if manifestUrl != "" {
		fmt.Printf("> **View manifest:** [%s](%s)\n\n", report.ImageName, manifestUrl)
	}

	fmt.Println()

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
		sortedMal := make([]string, len(report.MaliciousIssues))
		copy(sortedMal, report.MaliciousIssues)
		sort.Strings(sortedMal)
		for _, id := range sortedMal {
			fmt.Printf("| %s | %s |\n", id, severityLabel("Malicious"))
		}
		fmt.Println()
		fmt.Println("---")
		fmt.Println()
	}

	// Security findings table — collapsible, filtered by minSeverity, sorted Critical→Low then XRAY-ID.
	if !noFindings && len(report.SummaryIssues) > 0 {
		filtered := make([]SummaryIssue, 0, len(report.SummaryIssues))
		for _, si := range report.SummaryIssues {
			if severityMeetsMin(si.Severity, minSeverity) {
				filtered = append(filtered, si)
			}
		}
		sort.Slice(filtered, func(i, j int) bool {
			ri, rj := severityRank(filtered[i].Severity), severityRank(filtered[j].Severity)
			if ri != rj {
				return ri < rj
			}
			return filtered[i].IssueID < filtered[j].IssueID
		})
		if len(filtered) > 0 {
			fixableCount := 0
			for _, si := range filtered {
				if si.Fixable {
					fixableCount++
				}
			}
			fmt.Println()
			fmt.Println("---")
			fmt.Println()
			fmt.Printf("<details>\n<summary>Security Findings (%d | %d fixable) — click to expand</summary>\n\n", len(filtered), fixableCount)
			fmt.Println("| XRAY-ID | SEVERITY | JFROG SEVERITY | FIXABLE | PLATFORMS |")
			fmt.Println("|---------|----------|----------------|---------|-----------|")
			for _, si := range filtered {
				fixable := "No"
				if si.Fixable {
					fixable = "Yes"
				}
				platformsStr := strings.Join(si.Platforms, "<br>")
				if platformsStr == "" {
					platformsStr = "-"
				}
				fmt.Printf("| %s | %s | %s | %s | %s |\n",
					si.IssueID,
					severityLabel(si.Severity),
					jfrogSeverityLabel(si.JFrogSeverity, si.Severity),
					fixable,
					platformsStr,
				)
			}
			fmt.Println()
			fmt.Println("</details>")
			fmt.Println()
		}
	}

	fmt.Println("---")
	fmt.Println()
	fmt.Printf("> Xray scans trigger at upload time, but can be matched to new vulnerabilities over time without rescans.\n> These are findings as of %s.\n", report.GeneratedAt)
	fmt.Println()
	fmt.Printf("> Generated by %s %s\n", appName, appVersion)
	fmt.Println()

	return nil
}

// severityLabel returns an emoji-prefixed severity label for GitHub Markdown table cells.
func severityLabel(severity string) string {
	switch severity {
	case "Malicious":
		return ":skull: Malicious :skull:"
	case "Critical":
		return ":red_square: Critical"
	case "High":
		return ":orange_square: High"
	case "Medium":
		return ":yellow_square: Medium"
	case "Low":
		return ":brown_square: Low"
	default:
		return severity
	}
}

// jfrogSeverityLabel returns a colored badge for the JFrog Research severity, prefixed with
// :arrow_up_small: if JFrog rates it higher than the standard severity, or :arrow_down_small:
// if JFrog rates it lower. No prefix when the ratings match.
func jfrogSeverityLabel(jfrogSev, standardSev string) string {
	if jfrogSev == "" {
		return "-"
	}
	badge := severityLabel(jfrogSev)
	jr, sr := severityRank(jfrogSev), severityRank(standardSev)
	if jr < sr {
		return ":arrow_up_small: " + badge
	}
	if jr > sr {
		return ":arrow_down_small: " + badge
	}
	return badge
}

// severityRank returns a sort order for severity strings (lower = more severe).
func severityRank(s string) int {
	switch s {
	case "Malicious":
		return -1
	case "Critical":
		return 0
	case "High":
		return 1
	case "Medium":
		return 2
	case "Low":
		return 3
	default:
		return 4
	}
}

// severityMeetsMin returns true if severity is at least as severe as minSeverity.
// An empty or unrecognized minSeverity passes everything through.
func severityMeetsMin(severity, minSeverity string) bool {
	rank := map[string]int{"Malicious": -1, "Critical": 0, "High": 1, "Medium": 2, "Low": 3}
	minRank, ok := rank[minSeverity]
	if !ok {
		return true
	}
	r, ok := rank[severity]
	if !ok {
		return true
	}
	return r <= minRank
}

// ParseImageName splits an image reference into repository key, image name, and tag.
// Accepts "repo/image:tag" (repo from the argument) or "image:tag" (repo from defaultRepo).
// When the argument contains a slash before the first colon, the first segment is always the repo.
func ParseImageName(imageName, defaultRepo string) (string, string, string, error) {
	trimmed := strings.TrimSpace(imageName)
	if trimmed == "" {
		return "", "", "", fmt.Errorf("invalid image format, expected: image:tag")
	}

	if defaultRepo == "" {
		defaultRepo = "docker-local"
	}

	firstSlash := strings.Index(trimmed, "/")
	firstColon := strings.Index(trimmed, ":")

	var repoKey, imageAndTag string
	if firstSlash >= 0 && (firstColon < 0 || firstSlash < firstColon) {
		// Slash appears before any colon → first segment is the repo key.
		repoKey = trimmed[:firstSlash]
		imageAndTag = trimmed[firstSlash+1:]
	} else {
		// No slash, or slash comes after the colon → treat whole string as image:tag.
		repoKey = defaultRepo
		imageAndTag = trimmed
	}

	tagSeparator := strings.LastIndex(imageAndTag, ":")
	if tagSeparator <= 0 || tagSeparator == len(imageAndTag)-1 {
		return "", "", "", fmt.Errorf("invalid image format, expected: image:tag")
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
//  1. Discovers artifact paths via Artifactory AQL (handles both single and multi-platform images)
//  2. Optionally filters by --platform
//  3. Queries the malicious watch (GetViolations) per platform to build maliciousLookup
//  4. Queries the v2 summary API (GetSummaryV2) for severity counts and per-issue detail,
//     including fixable status and per-platform attribution; falls back to list.manifest.json
//     for multi-platform images if per-platform sha256__ paths return no results
//
// Returns the populated VulnerabilityReport and the maliciousLookup map (issue ID → true).
// SummaryIssues carries per-finding detail used by both JSON and markdown formatters.
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
		report.ImageNotFound = true
		return report, map[string]bool{}, nil
	}

	if !conf.Silent {
		log.Info(fmt.Sprintf("Discovered %d artifact path(s) for vulnerabilities", len(platformPaths)))
	}

	// Step 2: Apply platform filtering if specified.
	// --platform accepts "os/arch" (e.g., "linux/amd64") or OS only (e.g., "linux").
	if conf.Platform != "" {
		arch := ""
		osFilter := conf.Platform
		parts := strings.SplitN(conf.Platform, "/", 2)
		if len(parts) == 2 {
			osFilter = parts[0]
			arch = parts[1]
		}
		filtered := FilterManifestsByPlatform(platformPaths, arch, osFilter)
		if len(filtered) == 0 {
			if !conf.Silent {
				log.Warn(fmt.Sprintf("No platforms match filter (arch=%q, os=%q)", arch, osFilter))
			}
			return report, map[string]bool{}, nil
		}
		platformPaths = filtered
		if !conf.Silent {
			log.Info(fmt.Sprintf("After platform filtering: %d path(s) remaining", len(platformPaths)))
		}
	}

	if len(platformPaths) > 0 && platformPaths[0].isList {
		report.IsMultiPlatform = true
	}

	// Step 3: Query the malicious-only watch to resolve which issue IDs are malicious.
	// The Violations API's own malicious_package field is unreliable, so we use a dedicated
	// --malicious-watch-name watch as the source of truth.
	maliciousLookup := make(map[string]bool)

	if !conf.Silent {
		log.Info(fmt.Sprintf("Resolving malicious issue IDs from watch: %s", conf.MaliciousWatchName))
	}

	violationsErrCount := 0
	for _, dp := range platformPaths {
		maliciousResults, err := xraySvc.GetViolations(conf.MaliciousWatchName, extractRepoFromPath(dp.path), dp.path, conf.ProjectKey)
		if err != nil {
			log.Warn(fmt.Sprintf("Malicious watch query returned error for path %s: %v", dp.path, err))
			violationsErrCount++
			continue
		}
		for _, r := range maliciousResults {
			if r.Vulnerability.IssueId != "" {
				maliciousLookup[r.Vulnerability.IssueId] = true
			}
		}
		log.Debug(fmt.Sprintf("Malicious watch query for path %s returned %d violation(s)", dp.path, len(maliciousResults)))
	}
	if violationsErrCount > 0 && violationsErrCount == len(platformPaths) {
		return report, map[string]bool{}, fmt.Errorf("all malicious watch queries failed — cannot produce a reliable report")
	}

	// Query Xray v2 summary API for severity counts and per-issue detail.
	// Build one path+label per discovered platform for per-platform attribution in the findings table.
	isMultiPlatform := len(platformPaths) > 0 && platformPaths[0].isList

	v2Paths := make([]string, 0, len(platformPaths))
	v2Labels := make([]string, 0, len(platformPaths))
	for _, dp := range platformPaths {
		label := dp.os + "/" + dp.arch
		if dp.os == "" && dp.arch == "" {
			label = ""
		} else if dp.arch == "" {
			label = dp.os
		}
		v2Paths = append(v2Paths, conf.ProjectKey+"/"+dp.path)
		v2Labels = append(v2Labels, label)
	}

	counts, issues, err := xraySvc.GetSummaryV2(v2Paths, v2Labels)
	if err != nil {
		log.Warn(fmt.Sprintf("v2 summary API failed, counts will be 0: %v", err))
	} else if counts.Total == 0 && isMultiPlatform {
		// Per-platform sha256__ paths may not be indexed separately by Xray for multi-platform images.
		// Fall back to the top-level list.manifest.json path for combined counts.
		// Platform attribution is then set to all detected platforms for every finding.
		log.Info("Per-platform v2 query returned 0 results; falling back to list.manifest.json")
		listPath := conf.ProjectKey + "/" + repoKey + "/" + imageName + "/" + tag + "/list.manifest.json"
		counts, issues, err = xraySvc.GetSummaryV2([]string{listPath}, nil)
		if err != nil {
			log.Warn(fmt.Sprintf("v2 list.manifest.json fallback failed, counts will be 0: %v", err))
		} else {
			allLabels := make([]string, 0, len(v2Labels))
			for _, l := range v2Labels {
				if l != "" {
					allLabels = append(allLabels, l)
				}
			}
			for i := range issues {
				issues[i].Platforms = allLabels
			}
		}
	}

	if err == nil {
		report.TotalIssues = counts.Total
		report.CriticalCount = counts.Critical
		report.HighCount = counts.High
		report.MediumCount = counts.Medium
		report.LowCount = counts.Low
		report.SummaryIssues = issues
	}

	for _, dp := range platformPaths {
		var manifestDigest string
		if len(dp.digests) > 0 {
			manifestDigest = dp.digests[0]
		}
		report.Platforms = append(report.Platforms, PlatformVulnerabilityInfo{
			ManifestDigest: manifestDigest,
			Platform: Platform{
				OS:           dp.os,
				Architecture: dp.arch,
			},
		})
	}

	for issueID := range maliciousLookup {
		report.MaliciousIssues = append(report.MaliciousIssues, issueID)
	}
	sort.Strings(report.MaliciousIssues)

	return report, maliciousLookup, nil
}

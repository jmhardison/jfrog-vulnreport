// Package internal implements the core logic for the jfrog-vulnreport plugin: orchestrating Docker
// manifest discovery, Xray vulnerability queries via the Violations API, and report formatting.
package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/common"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	configCore "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	configBuilder "github.com/jfrog/jfrog-client-go/config"
	"github.com/jfrog/jfrog-client-go/http/jfroghttpclient"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xraySdk "github.com/jfrog/jfrog-client-go/xray"
	"golang.org/x/term"
)

// Constants for Docker media types recognized during manifest discovery.
const (
	MediaTypeManifest     = "application/vnd.docker.distribution.manifest.v2+json"
	MediaTypeManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
	MediaTypeOCIManifest  = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeOCIIndex     = "application/vnd.oci.image.index.v1+json"
)

// colorEnabled returns true when stdout is an interactive terminal that supports ANSI colors.
func colorEnabled() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// severityColor applies ANSI color to a severity string when colors are enabled.
// Malicious=bold red, Critical=red, High=yellow, Medium=cyan, Low=plain.
func severityColor(s string, enabled bool) string {
	if !enabled {
		return s
	}
	switch s {
	case "Malicious":
		return text.Colors{text.Bold, text.FgRed}.Sprint(s)
	case "Critical":
		return text.FgRed.Sprint(s)
	case "High":
		return text.FgYellow.Sprint(s)
	case "Medium":
		return text.FgCyan.Sprint(s)
	default:
		return s
	}
}

// setLogLevel configures the JFrog SDK logger based on the active CheckConfiguration:
//   - conf.Debug → DEBUG  (show everything, including pipeline trace messages)
//   - conf.Silent → ERROR (suppress all output; used by github-md to keep stdout clean)
//   - default → WARN      (show only warnings and errors; keeps JSON output clean)
func setLogLevel(conf *CheckConfiguration) {
	switch {
	case conf.Debug:
		log.SetLogger(log.NewLogger(log.DEBUG, os.Stderr))
	case conf.Silent:
		log.SetLogger(log.NewLogger(log.ERROR, os.Stderr))
	default:
		log.SetLogger(log.NewLogger(log.WARN, os.Stderr))
	}
}

// RunCheckCommand is the CLI entry point for the check command. It reads all flags from
// the components.Context, validates required fields, initializes SDK services via the
// JFrog CLI credential framework, and delegates to RunCheckCommandFromConf.
func RunCheckCommand(c *components.Context, appName, appVersion string) error {
	if len(c.Arguments) == 0 {
		return fmt.Errorf("image name is required. Usage: check <image:tag>")
	}
	if len(c.Arguments) > 1 {
		return fmt.Errorf("too many arguments. Expected: check <image:tag>")
	}

	output := c.GetStringFlagValue("output")
	if output == "" {
		output = "table"
	}

	conf := &CheckConfiguration{
		ImageName:          c.Arguments[0],
		ServerId:           c.GetStringFlagValue("server-id"),
		Platform:           c.GetStringFlagValue("platform"),
		FailOnVuln:         c.GetBoolFlagValue("fail-on-vuln"),
		Output:             output,
		Silent:             output == "github-md",
		MinSeverity:        c.GetStringFlagValue("min-severity"),
		Debug:              c.GetBoolFlagValue("debug"),
		DockerRegistryURL:  c.GetStringFlagValue("docker-registry-url"),
		ProjectKey:         c.GetStringFlagValue("project-key"),
		MaliciousWatchName: c.GetStringFlagValue("malicious-watch-name"),
		NoFindings:         c.GetBoolFlagValue("no-findings"),
		SaveOutput:         c.GetStringFlagValue("save-output"),
		AppName:            appName,
		AppVersion:         appVersion,
	}

	// Default project key to "default" if not specified.
	if conf.ProjectKey == "" {
		conf.ProjectKey = "default"
	}

	setLogLevel(conf)

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
	log.Debug(fmt.Sprintf("[XrayService] URL=%s", xraySvc.XrayDetails.GetUrl()))
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
	setLogLevel(conf)
	log.Debug(fmt.Sprintf("Checking vulnerabilities for image: %s/%s:%s", repoKey, imageName, tag))

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

	if conf.SaveOutput != "" {
		if err := saveOutputToFiles(conf, report, maliciousLookup, uiPortalManifestUrl); err != nil {
			return err
		}
	} else {
		if err := outputReport(os.Stdout, report, maliciousLookup, conf.Output, uiPortalManifestUrl, conf.MinSeverity, conf.NoFindings, conf.AppName, conf.AppVersion); err != nil {
			return fmt.Errorf("failed to output report: %w", err)
		}
	}

	if conf.FailOnVuln && report.TotalIssues > 0 {
		return fmt.Errorf("found %d vulnerability issues", report.TotalIssues)
	}

	return nil
}

// saveOutputToFiles writes each format listed in conf.SaveOutput to its corresponding file
// in the current working directory, then prints a confirmation line to stdout.
// Supported formats: "json" → vulnreport.json, "github-md" → vulnreport.md.
func saveOutputToFiles(conf *CheckConfiguration, report *VulnerabilityReport, maliciousLookup map[string]bool, uiPortalManifestUrl string) error {
	formats := strings.Split(conf.SaveOutput, ",")
	var savedFiles []string

	for _, rawFmt := range formats {
		format := strings.TrimSpace(rawFmt)
		switch format {
		case "json":
			f, err := os.Create("vulnreport.json")
			if err != nil {
				return fmt.Errorf("failed to create vulnreport.json: %w", err)
			}
			defer f.Close()
			if err := outputJSONReport(f, report, maliciousLookup, conf.AppName, conf.AppVersion); err != nil {
				return fmt.Errorf("failed to write vulnreport.json: %w", err)
			}
			savedFiles = append(savedFiles, "vulnreport.json")
		case "github-md":
			f, err := os.Create("vulnreport.md")
			if err != nil {
				return fmt.Errorf("failed to create vulnreport.md: %w", err)
			}
			defer f.Close()
			if err := outputMarkdownReport(f, report, maliciousLookup, uiPortalManifestUrl, conf.MinSeverity, conf.NoFindings, conf.AppName, conf.AppVersion); err != nil {
				return fmt.Errorf("failed to write vulnreport.md: %w", err)
			}
			savedFiles = append(savedFiles, "vulnreport.md")
		default:
			return fmt.Errorf("unsupported --save-output format %q: use 'json' and/or 'github-md'", format)
		}
	}

	fmt.Printf("Saved: %s\n", strings.Join(savedFiles, ", "))
	return nil
}

// generateSecurityBanner renders a GitHub-flavored alert banner based on the highest-severity finding tier:
//   - Malicious detected → [!CAUTION] red banner (always takes priority)
//   - Critical CVEs, no malicious → [!CAUTION] orange banner
//   - Non-critical CVEs, no malicious → [!WARNING] yellow banner
//   - No findings → [!NOTE] green banner
func generateSecurityBanner(w io.Writer, report *VulnerabilityReport, maliciousLookup map[string]bool) {
	hasMalicious := len(maliciousLookup) > 0 || len(report.MaliciousIssues) > 0
	hasCritical := report.CriticalCount > 0
	hasFindings := report.TotalIssues > 0

	switch {
	case hasMalicious:
		// RED banner for malicious content
		fmt.Fprintln(w, "![Malicious](https://raw.githubusercontent.com/jmhardison/jfrog-vulnreport/main/images/badge-malicious.png)")
		fmt.Fprintln(w, "---")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "> [!CAUTION]")
		fmt.Fprintln(w, "> ## :rotating_light: MALICIOUS EXPLOIT PRESENT :rotating_light:")
		fmt.Fprintln(w, "> **IMMEDIATE ACTION REQUIRED** - Malicious content detected in this image. Remediate or seek guidance.")
		fmt.Fprintln(w, "> Policies can prevent the download and execution of this image, resulting in potential deploy issues such as `imagePullBackoff`.")
		fmt.Fprintln(w, "> Do `not` promote until confirmed, and stop use of image if not a false positive.")
		fmt.Fprintln(w)
		fmt.Fprintln(w)
		fmt.Fprintln(w, "---")
		fmt.Fprintln(w)
	case hasCritical:
		// ORANGE banner for critical CVEs (no malicious)
		fmt.Fprintln(w, "![Critical CVEs](https://raw.githubusercontent.com/jmhardison/jfrog-vulnreport/main/images/badge-critical-cve.png)")
		fmt.Fprintln(w, "---")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "> [!CAUTION]")
		fmt.Fprintln(w, "> ## :red_circle: CRITICAL CVE'S PRESENT")
		fmt.Fprintln(w, "> Critical severity vulnerabilities found - review and remediation required.")
		fmt.Fprintln(w, "> Fixable critical issues should be resolved before promotion.")
		fmt.Fprintln(w)
		fmt.Fprintln(w)
		fmt.Fprintln(w, "---")
		fmt.Fprintln(w)
	case hasFindings:
		// YELLOW banner for non-critical CVEs present
		fmt.Fprintln(w, "![CVEs Present](https://raw.githubusercontent.com/jmhardison/jfrog-vulnreport/main/images/badge-cves-present.png)")
		fmt.Fprintln(w, "---")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "> [!WARNING]")
		fmt.Fprintln(w, "> ## :warning: CVE's PRESENT")
		fmt.Fprintln(w, "> Security vulnerabilities found - review and remediate as needed")
		fmt.Fprintln(w, "> Promotion won't be blocked, however fixable issues should be resolved before promotion when possible.")
		fmt.Fprintln(w)
		fmt.Fprintln(w)
		fmt.Fprintln(w, "---")
		fmt.Fprintln(w)
	default:
		// GREEN banner for clean image
		fmt.Fprintln(w, "![No Findings](https://raw.githubusercontent.com/jmhardison/jfrog-vulnreport/main/images/badge-no-findings.png)")
		fmt.Fprintln(w, "---")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "> [!NOTE]")
		fmt.Fprintln(w, "> ## :white_check_mark: NO FINDINGS")
		fmt.Fprintln(w, "> No security issues found - image appears clean")
		fmt.Fprintln(w)
		fmt.Fprintln(w)
		fmt.Fprintln(w, "---")
		fmt.Fprintln(w)
	}
}

// outputTableReport renders a human-friendly CLI report using Unicode box-drawing tables.
// Sections: header, status banner, security summary, malicious findings (when present),
// security findings table (filtered/sorted), footer. ANSI colors are enabled only when
// stdout is an interactive terminal.
func outputTableReport(w io.Writer, report *VulnerabilityReport, maliciousLookup map[string]bool, manifestUrl string, minSeverity string, noFindings bool, appName, appVersion string) error {
	colors := colorEnabled()

	// --- Header ---
	fmt.Fprintf(w, "Xray Security Report: %s\n", report.ImageName)
	if manifestUrl != "" {
		fmt.Fprintln(w, manifestUrl)
	}
	fmt.Fprintln(w)

	if report.ImageNotFound {
		fmt.Fprintln(w, "No Image Found — check the image name/tag, or that publishing is complete.")
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Generated by %s %s\n", appName, appVersion)
		return nil
	}

	// --- Status banner ---
	hasMalicious := len(report.MaliciousIssues) > 0
	hasCritical := report.CriticalCount > 0
	hasFindings := report.TotalIssues > 0
	switch {
	case hasMalicious:
		msg := "MALICIOUS EXPLOIT PRESENT — immediate action required"
		if colors {
			msg = text.Colors{text.Bold, text.FgRed}.Sprint(msg)
		}
		fmt.Fprintf(w, "⚠ STATUS: %s\n\n", msg)
	case hasCritical:
		msg := "CRITICAL CVEs PRESENT — review and remediation required"
		if colors {
			msg = text.FgRed.Sprint(msg)
		}
		fmt.Fprintf(w, "⚠ STATUS: %s\n\n", msg)
	case hasFindings:
		msg := "CVEs PRESENT — review and remediate as needed"
		if colors {
			msg = text.FgYellow.Sprint(msg)
		}
		fmt.Fprintf(w, "⚠ STATUS: %s\n\n", msg)
	default:
		msg := "NO FINDINGS — image appears clean"
		if colors {
			msg = text.FgGreen.Sprint(msg)
		}
		fmt.Fprintf(w, "✓ STATUS: %s\n\n", msg)
	}

	// --- Security Summary table ---
	maliciousCount := len(report.MaliciousIssues)
	fixableCount := 0
	for _, si := range report.SummaryIssues {
		if si.Fixable {
			fixableCount++
		}
	}
	var platformLabels []string
	for _, p := range report.Platforms {
		platformLabels = append(platformLabels, p.Platform.OS+"/"+p.Platform.Architecture)
	}

	fmt.Fprintln(w, "Security Summary")
	sumT := table.NewWriter()
	sumT.SetOutputMirror(w)
	sumT.SetStyle(table.StyleLight)
	sumT.Style().Options.SeparateHeader = false
	sumT.AppendRows([]table.Row{
		{"Total Findings", report.TotalIssues},
		{"Critical", report.CriticalCount},
		{"High", report.HighCount},
		{"Medium", report.MediumCount},
		{"Low", report.LowCount},
		{"Fixable", fixableCount},
		{"Malicious", maliciousCount},
		{"Platforms", fmt.Sprintf("%d (%s)", len(report.Platforms), strings.Join(platformLabels, ", "))},
	})
	sumT.Render()
	fmt.Fprintln(w)

	// --- Malicious Findings table ---
	if maliciousCount > 0 {
		sortedMal := make([]string, len(report.MaliciousIssues))
		copy(sortedMal, report.MaliciousIssues)
		sort.Strings(sortedMal)

		fmt.Fprintf(w, "Malicious Findings (%d)\n", maliciousCount)
		malT := table.NewWriter()
		malT.SetOutputMirror(w)
		malT.SetStyle(table.StyleLight)
		malT.AppendHeader(table.Row{"XRAY-ID", "SEVERITY"})
		for _, id := range sortedMal {
			malT.AppendRow(table.Row{id, severityColor("Malicious", colors)})
		}
		malT.Render()
		fmt.Fprintln(w)
	}

	// --- Security Findings table ---
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
			fCount := 0
			for _, si := range filtered {
				if si.Fixable {
					fCount++
				}
			}
			fmt.Fprintf(w, "Security Findings (%d | %d fixable)\n", len(filtered), fCount)
			findT := table.NewWriter()
			findT.SetOutputMirror(w)
			findT.SetStyle(table.StyleLight)
			findT.AppendHeader(table.Row{"XRAY-ID", "SEVERITY", "JFROG SEVERITY", "FIXABLE", "PLATFORMS"})
			for _, si := range filtered {
				fixable := "No"
				if si.Fixable {
					fixable = "Yes"
				}
				jfrogSev := si.JFrogSeverity
				if jfrogSev == "" {
					jfrogSev = "-"
				}
				platforms := strings.Join(si.Platforms, ", ")
				if platforms == "" {
					platforms = "-"
				}
				displaySev := si.Severity
				if maliciousLookup[si.IssueID] {
					displaySev = "Malicious"
				}
				findT.AppendRow(table.Row{
					si.IssueID,
					severityColor(displaySev, colors),
					severityColor(jfrogSev, colors),
					fixable,
					platforms,
				})
			}
			findT.Render()
			fmt.Fprintln(w)
		}
	}

	// --- Footer ---
	fmt.Fprintf(w, "Generated by %s %s at %s\n", appName, appVersion, report.GeneratedAt)

	return nil
}

// outputReport dispatches to the appropriate formatter based on the requested output format.
// manifestUrl is used by github-md output to render a clickable link to the image's manifest in JFrog Platform UI —
// no additional API calls needed, just URL construction from server config.
func outputReport(w io.Writer, report *VulnerabilityReport, maliciousLookup map[string]bool, output string, manifestUrl string, minSeverity string, noFindings bool, appName, appVersion string) error {
	switch output {
	case "table":
		return outputTableReport(w, report, maliciousLookup, manifestUrl, minSeverity, noFindings, appName, appVersion)
	case "json":
		return outputJSONReport(w, report, maliciousLookup, appName, appVersion)
	case "github-md":
		return outputMarkdownReport(w, report, maliciousLookup, manifestUrl, minSeverity, noFindings, appName, appVersion)
	default:
		return fmt.Errorf("unsupported output format: %s. Use 'table', 'json', or 'github-md'", output)
	}
}

// outputJSONReport converts the VulnerabilityReport to an EnhancedVulnerabilityReport (with per-finding
// malicious status and issue type counts), then prints it as indented JSON to w.
func outputJSONReport(w io.Writer, report *VulnerabilityReport, maliciousLookup map[string]bool, appName, appVersion string) error {
	// Convert to enhanced format using pre-built malicious lookup (no Events API calls needed).
	enhanced := convertToEnhancedReport(report, maliciousLookup, appName, appVersion)

	jsonData, err := json.MarshalIndent(enhanced, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Fprintln(w, string(jsonData))
	return nil
}

// convertToEnhancedReport builds an EnhancedVulnerabilityReport from a VulnerabilityReport.
// Per-issue detail from SummaryIssues is serialized as the top-level Findings array; malicious
// status on each finding is resolved from maliciousLookup (built from the Violations API).
func convertToEnhancedReport(report *VulnerabilityReport, maliciousLookup map[string]bool, appName, appVersion string) *EnhancedVulnerabilityReport {
	var findings []EnhancedFinding
	fixableCount := 0
	for _, si := range report.SummaryIssues {
		if si.Fixable {
			fixableCount++
		}
		findings = append(findings, EnhancedFinding{
			IssueID:       si.IssueID,
			Severity:      si.Severity,
			JFrogSeverity: si.JFrogSeverity,
			Fixable:       si.Fixable,
			Malicious:     maliciousLookup[si.IssueID],
			Platforms:     si.Platforms,
		})
	}
	sort.Slice(findings, func(i, j int) bool {
		ri, rj := severityRank(findings[i].Severity), severityRank(findings[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return findings[i].IssueID < findings[j].IssueID
	})

	var platforms []EnhancedPlatformInfo
	for _, p := range report.Platforms {
		platforms = append(platforms, EnhancedPlatformInfo{Platform: p.Platform})
	}

	var maliciousIssues []string
	if len(report.MaliciousIssues) > 0 {
		maliciousIssues = report.MaliciousIssues
	}

	return &EnhancedVulnerabilityReport{
		ImageName:       report.ImageName,
		GeneratedAt:     report.GeneratedAt,
		PluginName:      appName,
		PluginVersion:   appVersion,
		ImageNotFound:   report.ImageNotFound,
		MaliciousIssues: maliciousIssues,
		Summary: SecuritySummary{
			TotalFindings:  report.TotalIssues,
			CriticalCount:  report.CriticalCount,
			HighCount:      report.HighCount,
			MediumCount:    report.MediumCount,
			LowCount:       report.LowCount,
			FixableCount:   fixableCount,
			MaliciousCount: len(maliciousLookup),
			PlatformCount:  len(report.Platforms),
		},
		Platforms: platforms,
		Findings:  findings,
	}
}

// outputMarkdownReport generates a GitHub-flavored markdown security report. Uses the pre-built malicious
// lookup map (no Events API calls) for per-finding malicious status and summary counts. The manifestUrl
// parameter is used to render a clickable link to the image's manifest in JFrog Platform UI —
// constructed as <baseUrl>/ui/repos/tree/General/<repo>/<path>/list.manifest.json without additional HTTP requests.
func outputMarkdownReport(w io.Writer, report *VulnerabilityReport, maliciousLookup map[string]bool, manifestUrl string, minSeverity string, noFindings bool, appName, appVersion string) error {
	if report.ImageNotFound {
		fmt.Fprintln(w, "![No Image Found](https://raw.githubusercontent.com/jmhardison/jfrog-vulnreport/main/images/badge-no-image-found.png)")
		fmt.Fprintln(w, "---")
		fmt.Fprintln(w)
		fmt.Fprintf(w, "# Xray Security Report\n\n")
		fmt.Fprintf(w, "## %s\n\n", report.ImageName)
		fmt.Fprintln(w, "No Image Found - Check the image name/tag, or that publishing is complete.")
		fmt.Fprintln(w)
		fmt.Fprintf(w, "> Generated by %s %s\n", appName, appVersion)
		fmt.Fprintln(w)
		return nil
	}

	generateSecurityBanner(w, report, maliciousLookup)

	fmt.Fprintf(w, "# Xray Security Report\n\n")
	fmt.Fprintf(w, "## %s\n\n", report.ImageName)

	if manifestUrl != "" {
		fmt.Fprintf(w, "> **View manifest:** [%s](%s)\n\n", report.ImageName, manifestUrl)
	}

	fmt.Fprintln(w)

	fmt.Fprintln(w, "## Security Summary")

	maliciousCount := len(report.MaliciousIssues)
	fmt.Fprintf(w, "- **Total Findings:** %d\n", report.TotalIssues)
	fmt.Fprintf(w, "- **Critical:** %d | **High:** %d | **Medium:** %d | **Low:** %d\n",
		report.CriticalCount, report.HighCount, report.MediumCount, report.LowCount)
	fmt.Fprintf(w, "- **Malicious:** %d\n", maliciousCount)
	fmt.Fprintf(w, "- **Platforms Scanned:** %d\n", len(report.Platforms))
	if len(report.Platforms) > 0 {
		var platformList []string
		for _, p := range report.Platforms {
			platformList = append(platformList, fmt.Sprintf("%s/%s", p.Platform.OS, p.Platform.Architecture))
		}
		fmt.Fprintf(w, "- **Platforms:** %s\n\n", strings.Join(platformList, ", "))
	} else {
		fmt.Fprintln(w)
	}

	if maliciousCount > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "---")
		fmt.Fprintln(w)
		fmt.Fprintf(w, "## :bangbang: Malicious Findings (%d)\n", maliciousCount)
		fmt.Fprintln(w, "| Xray ID | Severity |")
		fmt.Fprintln(w, "|---------|----------|")
		sortedMal := make([]string, len(report.MaliciousIssues))
		copy(sortedMal, report.MaliciousIssues)
		sort.Strings(sortedMal)
		for _, id := range sortedMal {
			fmt.Fprintf(w, "| %s | %s |\n", id, severityLabel("Malicious"))
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, "---")
		fmt.Fprintln(w)
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
			fmt.Fprintln(w)
			fmt.Fprintln(w, "---")
			fmt.Fprintln(w)
			fmt.Fprintf(w, "<details>\n<summary>Security Findings (%d | %d fixable) — click to expand</summary>\n\n", len(filtered), fixableCount)
			fmt.Fprintln(w, "| XRAY-ID | SEVERITY | JFROG SEVERITY | FIXABLE | PLATFORMS |")
			fmt.Fprintln(w, "|---------|----------|----------------|---------|-----------|")
			for _, si := range filtered {
				fixable := "No"
				if si.Fixable {
					fixable = "Yes"
				}
				platformsStr := strings.Join(si.Platforms, "<br>")
				if platformsStr == "" {
					platformsStr = "-"
				}
				fmt.Fprintf(w, "| %s | %s | %s | %s | %s |\n",
					si.IssueID,
					severityLabel(si.Severity),
					jfrogSeverityLabel(si.JFrogSeverity, si.Severity),
					fixable,
					platformsStr,
				)
			}
			fmt.Fprintln(w)
			fmt.Fprintln(w, "</details>")
			fmt.Fprintln(w)
		}
	}

	fmt.Fprintln(w, "---")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "> Xray scans trigger at upload time, but can be matched to new vulnerabilities over time without rescans.\n> These are findings as of %s.\n", report.GeneratedAt)
	fmt.Fprintf(w, "> Generated by %s %s\n", appName, appVersion)
	fmt.Fprintln(w)

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
	log.Debug(fmt.Sprintf("Generating vulnerability report for %s/%s:%s", repoKey, imageName, tag))

	report := &VulnerabilityReport{
		ImageName:   fmt.Sprintf("%s/%s:%s", repoKey, imageName, tag),
		GeneratedAt: time.Now().Format(time.RFC3339),
		Platforms:   []PlatformVulnerabilityInfo{},
	}

	// Step 1: Dual-path discovery (handles both single-platform and multi-platform images)
	log.Debug("Running dual-path manifest discovery...")
	platformPaths, err := discoverImageArtifacts(artSvc, repoKey, imageName, tag)
	if err != nil {
		return nil, nil, fmt.Errorf("manifest discovery failed: %w", err)
	}

	if len(platformPaths) == 0 {
		log.Warn("No artifacts discovered — image may not be indexed in Xray or may use an unexpected path format")
		report.ImageNotFound = true
		return report, map[string]bool{}, nil
	}

	log.Debug(fmt.Sprintf("Discovered %d artifact path(s) for vulnerabilities", len(platformPaths)))

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
			log.Warn(fmt.Sprintf("No platforms match filter (arch=%q, os=%q)", arch, osFilter))
			return report, map[string]bool{}, nil
		}
		platformPaths = filtered
		log.Debug(fmt.Sprintf("After platform filtering: %d path(s) remaining", len(platformPaths)))
	}

	if len(platformPaths) > 0 && platformPaths[0].isList {
		report.IsMultiPlatform = true
	}

	// Step 3: Query the malicious-only watch to resolve which issue IDs are malicious.
	// The Violations API's own malicious_package field is unreliable, so we use a dedicated
	// --malicious-watch-name watch as the source of truth.
	maliciousLookup := make(map[string]bool)

	log.Debug(fmt.Sprintf("Resolving malicious issue IDs from watch: %s", conf.MaliciousWatchName))

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
		log.Debug("Per-platform v2 query returned 0 results; falling back to list.manifest.json")
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

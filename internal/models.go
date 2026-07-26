// Package internal implements the core logic for the jfrog-vulnreport plugin.
// It orchestrates Docker manifest discovery, Xray vulnerability queries via the
// Violations API, and report formatting in JSON or GitHub Markdown.
package internal

import (
	"net/http"

	"github.com/jfrog/jfrog-client-go/xray/services"
)


// DockerManifest represents a single-platform Docker image manifest (v2 schema).
// Stored in Artifactory under <repo>/<image>/<tag>/manifest.json.
type DockerManifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        Descriptor   `json:"config"`
	Layers        []Descriptor `json:"layers"`
}

// ManifestList represents a multi-platform Docker image index (list manifest).
// Stored in Artifactory under <repo>/<image>/<tag>/list.manifest.json. Contains one
// PlatformManifest entry per OS/architecture combination.
type ManifestList struct {
	SchemaVersion int                `json:"schemaVersion"`
	MediaType     string             `json:"mediaType"`
	Manifests     []PlatformManifest `json:"manifests"`
}

// PlatformManifest is a single platform-specific manifest within a ManifestList.
type PlatformManifest struct {
	Descriptor
	Platform Platform `json:"platform"`
}

// Platform describes the OS and architecture of a container image variant.
type Platform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant,omitempty"` // e.g., "v7" for arm/v7
}

// Descriptor identifies a Docker layer or config by media type, digest, and size.
type Descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// CheckConfiguration holds all parameters for a vulnerability check invocation.
// Populated from CLI flags in commands/check.go and passed through the call chain.
type CheckConfiguration struct {
	ImageName         string // Full image reference (e.g., "docker-local/myimage:latest" or "myimage:latest")
	ServerId          string // JFrog CLI server configuration ID
	Platform          string // Platform filter: "os/arch" (e.g., "linux/amd64") or OS only (e.g., "linux")
	FailOnVuln        bool   // Exit non-zero if any vulnerabilities found
	Output            string // Output format: "json" or "github-md"
	Silent            bool   // Suppress all log output (used by github-md mode)
	MinSeverity       string // Minimum severity to display: Low, Medium, High, Critical, Malicious
	Debug             bool   // Enable debug-level logging (set by --debug flag)
	DockerRegistryURL string // Override URL for Docker registry (for direct manifest fetch)
	ProjectKey        string // Xray project key for violation queries (defaults to "default")
	MaliciousWatchName string // Required: Xray watch that defines malicious packages (source of truth for malicious detection)
	NoFindings         bool   // Suppress Security Findings table in output (summary and malicious findings still shown)
	SaveOutput         string // Comma-separated formats to save to files: "json" and/or "github-md"
	AppName            string // Plugin name, set by main.go and threaded through for footer rendering
	AppVersion         string // Plugin version, set by main.go and threaded through for footer rendering
}

// VulnerabilityReport is the core report structure returned by generateVulnerabilityReport.
// Contains per-platform vulnerability groups with raw services.Vulnerability data from Xray.
type VulnerabilityReport struct {
	ImageName        string                      `json:"imageName"`
	Platforms        []PlatformVulnerabilityInfo `json:"platforms"`
	TotalIssues      int                         `json:"totalIssues"`
	CriticalCount    int                         `json:"criticalCount"`
	HighCount        int                         `json:"highCount"`
	MediumCount      int                         `json:"mediumCount"`
	LowCount         int                         `json:"lowCount"`
	GeneratedAt      string                      `json:"generatedAt"`
	IsMultiPlatform   bool           `json:"isMultiPlatform,omitempty"` // true if list.manifest.json was expanded into per-platform entries
	MaliciousIssues   []string       `json:"maliciousIssues,omitempty"` // issue IDs returned by the malicious watch
	SummaryIssues     []SummaryIssue `json:"-"`                         // per-issue detail from v2 summary API; not serialized
	ImageNotFound     bool           `json:"imageNotFound,omitempty"`   // true when no Artifactory artifacts were discovered for the image
}

// PlatformVulnerabilityInfo groups vulnerabilities discovered for a single platform variant.
type PlatformVulnerabilityInfo struct {
	Platform        Platform                 `json:"platform"`
	ManifestDigest  string                   `json:"manifestDigest"` // sha256 digest of the manifest
	Vulnerabilities []services.Vulnerability `json:"vulnerabilities"`
	LayerCount      int                      `json:"layerCount"`
	TotalSize       int64                    `json:"totalSize"` // Total uncompressed size in bytes
}

// DockerRegistryClient handles HTTP requests to a Docker registry for manifest retrieval.
type DockerRegistryClient struct {
	BaseURL    string
	HTTPClient *http.Client
	Username   string
	Password   string
	Token      string
}

// EnhancedVulnerabilityReport is the JSON output format — a flattened, aggregated view of
// VulnerabilityReport suitable for machine consumption. Includes per-finding detail from the
// Xray v2 summary API and malicious issue IDs from the malicious watch.
type EnhancedVulnerabilityReport struct {
	ImageName       string                 `json:"imageName"`
	GeneratedAt     string                 `json:"generatedAt"`
	PluginName      string                 `json:"pluginName,omitempty"`
	PluginVersion   string                 `json:"pluginVersion,omitempty"`
	ImageNotFound   bool                   `json:"imageNotFound,omitempty"`
	Summary         SecuritySummary        `json:"summary"`
	MaliciousIssues []string               `json:"maliciousIssues,omitempty"`
	Platforms       []EnhancedPlatformInfo `json:"platforms"`
	Findings        []EnhancedFinding      `json:"findings,omitempty"`
}

// SecuritySummary provides aggregate counts across all platforms. MaliciousCount is derived from
// the --malicious-watch-name watch as the source of truth for malicious detection.
type SecuritySummary struct {
	TotalFindings  int `json:"totalFindings"`
	CriticalCount  int `json:"criticalCount"`
	HighCount      int `json:"highCount"`
	MediumCount    int `json:"mediumCount"`
	LowCount       int `json:"lowCount"`
	FixableCount   int `json:"fixableCount"`
	MaliciousCount int `json:"maliciousCount"`
	PlatformCount  int `json:"platformCount"`
}

// EnhancedPlatformInfo is a flattened representation of PlatformVulnerabilityInfo for JSON output.
type EnhancedPlatformInfo struct {
	Platform Platform `json:"platform"`
}

// EnhancedFinding is a single vulnerability finding in the JSON report, populated from the
// Xray v2 summary API. Malicious is true when the issue ID was returned by the --malicious-watch-name watch.
type EnhancedFinding struct {
	IssueID       string   `json:"issueId"`
	Severity      string   `json:"severity"`
	JFrogSeverity string   `json:"jfrogSeverity,omitempty"`
	Fixable       bool     `json:"fixable"`
	Malicious     bool     `json:"malicious"`
	Platforms     []string `json:"platforms,omitempty"`
}

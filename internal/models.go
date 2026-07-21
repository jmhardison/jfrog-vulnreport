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
	ImageName         string // Full image reference (e.g., "docker-local/myimage:latest")
	ServerId          string // JFrog CLI server configuration ID
	Platform          string // Platform filter in "os/arch" format (e.g., "linux/amd64")
	OS                string // OS filter (extracted from Platform if not set separately)
	FailOnVuln        bool   // Exit non-zero if any vulnerabilities found
	Output            string // Output format: "json" or "github-md"
	Silent            bool   // Suppress all log output (used by github-md mode)
	MinSeverity       string // Minimum severity to display: Low, Medium, High, Critical, Malicious
	ShowFindings      bool   // Include detailed findings table in markdown output
	DebugPaths        bool   // Log artifact discovery paths for troubleshooting
	DockerRegistryURL string // Override URL for Docker registry (for direct manifest fetch)
	ProjectKey        string // Xray project key for violation queries (defaults to "default")
	WatchName         string // JFrog Xray watch name — filters violations to those relevant to the user's watch
	MaliciousWatchName string // Required: Xray watch that defines malicious packages (source of truth for malicious detection)
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
	IsMultiPlatform   bool         `json:"isMultiPlatform,omitempty"` // true if list.manifest.json was expanded into per-platform entries
	OrphanedMalicious []string     `json:"orphanedMalicious,omitempty"` // malicious IDs from watch not returned as violations by report watch
	WatchFiltered     bool         `json:"-"`                           // true when --watch-name was set; gates the findings table in output
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
// VulnerabilityReport suitable for machine consumption. Includes per-finding malicious status
// and issue type counts derived from the Violations API response.
type EnhancedVulnerabilityReport struct {
	ImageName   string                 `json:"imageName"`
	GeneratedAt string                 `json:"generatedAt"`
	Summary     SecuritySummary        `json:"summary"`
	IssueTypes  map[string]int         `json:"issueTypes"` // Issue type → count (CVE, Malware, etc.)
	Platforms   []EnhancedPlatformInfo `json:"platforms"`
}

// SecuritySummary provides aggregate counts across all platforms. MaliciousCount is derived from
// the --malicious-watch-name watch as the source of truth for malicious detection.
type SecuritySummary struct {
	TotalFindings  int `json:"totalFindings"`
	CriticalCount  int `json:"criticalCount"`
	HighCount      int `json:"highCount"`
	MediumCount    int `json:"mediumCount"`
	LowCount       int `json:"lowCount"`
	MaliciousCount int `json:"maliciousCount"`
	PlatformCount  int `json:"platformCount"`
}

// EnhancedPlatformInfo is a flattened representation of PlatformVulnerabilityInfo for JSON output.
type EnhancedPlatformInfo struct {
	Platform      Platform         `json:"platform"`
	FindingsCount int              `json:"findingsCount"`
	LayerCount    int              `json:"layerCount"`
	SizeMB        float64          `json:"sizeMB"`
	Findings      []CompactFinding `json:"findings"`
}

// CompactFinding is a single vulnerability finding in the enhanced report. Malicious indicates
// whether the issue ID was found in the --malicious-watch-name watch (source of truth).
type CompactFinding struct {
	IssueId   string `json:"issueId"`
	Type      string `json:"type"`        // Issue type: CVE, Malware, License, etc.
	Severity  string `json:"severity"`    // Low, Medium, High, Critical
	Malicious bool   `json:"malicious"`   // True if issue ID was found in the --malicious-watch-name watch
	CveCount  int    `json:"cveCount"`    // Number of CVEs associated with this finding
}

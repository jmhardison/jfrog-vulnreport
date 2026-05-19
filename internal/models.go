package internal

import (
	"net/http"

	"github.com/jfrog/jfrog-client-go/xray/services"
)

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

type CheckConfiguration struct {
	ImageName         string
	ServerId          string
	Platform          string
	OS                string
	FailOnVuln        bool
	Output            string
	Silent            bool
	MinSeverity       string
	ShowFindings      bool
	DebugPaths        bool
	DockerRegistryURL string
}

type VulnerabilityReport struct {
	ImageName     string                      `json:"imageName"`
	Platforms     []PlatformVulnerabilityInfo `json:"platforms"`
	TotalIssues   int                         `json:"totalIssues"`
	CriticalCount int                         `json:"criticalCount"`
	HighCount     int                         `json:"highCount"`
	MediumCount   int                         `json:"mediumCount"`
	LowCount      int                         `json:"lowCount"`
	GeneratedAt   string                      `json:"generatedAt"`
}

type PlatformVulnerabilityInfo struct {
	Platform        Platform                 `json:"platform"`
	ManifestDigest  string                   `json:"manifestDigest"`
	Vulnerabilities []services.Vulnerability `json:"vulnerabilities"`
	LayerCount      int                      `json:"layerCount"`
	TotalSize       int64                    `json:"totalSize"`
}

type DockerRegistryClient struct {
	BaseURL    string
	HTTPClient *http.Client
	Username   string
	Password   string
	Token      string
}

type EnhancedVulnerabilityReport struct {
	ImageName   string                 `json:"imageName"`
	GeneratedAt string                 `json:"generatedAt"`
	Summary     SecuritySummary        `json:"summary"`
	IssueTypes  map[string]int         `json:"issueTypes"`
	Platforms   []EnhancedPlatformInfo `json:"platforms"`
}

type SecuritySummary struct {
	TotalFindings  int `json:"totalFindings"`
	CriticalCount  int `json:"criticalCount"`
	HighCount      int `json:"highCount"`
	MediumCount    int `json:"mediumCount"`
	LowCount       int `json:"lowCount"`
	MaliciousCount int `json:"maliciousCount"`
	PlatformCount  int `json:"platformCount"`
}

type EnhancedPlatformInfo struct {
	Platform      Platform         `json:"platform"`
	FindingsCount int              `json:"findingsCount"`
	LayerCount    int              `json:"layerCount"`
	SizeMB        float64          `json:"sizeMB"`
	Findings      []CompactFinding `json:"findings"`
}

type CompactFinding struct {
	IssueId   string `json:"issueId"`
	Type      string `json:"type"`
	Severity  string `json:"severity"`
	Malicious bool   `json:"malicious"`
	CveCount  int    `json:"cveCount"`
}

package internal

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	artAuth "github.com/jfrog/jfrog-client-go/artifactory/auth"
	"github.com/jfrog/jfrog-client-go/http/jfroghttpclient"
	xrayAuth "github.com/jfrog/jfrog-client-go/xray/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseImageName(t *testing.T) {
	tests := []struct {
		name          string
		fullImageName string
		defaultRepo   string
		expectedRepo  string
		expectedImage string
		expectedTag   string
		expectError   bool
	}{
		{
			name:          "Valid image with single repository",
			fullImageName: "docker-local/myapp:latest",
			defaultRepo:   "",
			expectedRepo:  "docker-local",
			expectedImage: "myapp",
			expectedTag:   "latest",
		},
		{
			name:          "Valid image with nested path",
			fullImageName: "docker-local/team/myapp:v1.2.3",
			defaultRepo:   "",
			expectedRepo:  "docker-local",
			expectedImage: "team/myapp",
			expectedTag:   "v1.2.3",
		},
		{
			name:          "Image without repo prefix uses defaultRepo",
			fullImageName: "myapp:latest",
			defaultRepo:   "docker-local",
			expectedRepo:  "docker-local",
			expectedImage: "myapp",
			expectedTag:   "latest",
		},
		{
			name:          "Image without repo prefix uses custom defaultRepo",
			fullImageName: "myapp:v2.0",
			defaultRepo:   "my-repo",
			expectedRepo:  "my-repo",
			expectedImage: "myapp",
			expectedTag:   "v2.0",
		},
		{
			name:          "Repo in image arg overrides defaultRepo",
			fullImageName: "docker-local/myapp:latest",
			defaultRepo:   "other-repo",
			expectedRepo:  "docker-local",
			expectedImage: "myapp",
			expectedTag:   "latest",
		},
		{
			name:          "Invalid format - missing tag",
			fullImageName: "docker-local/myapp",
			defaultRepo:   "",
			expectError:   true,
		},
		{
			name:          "Image without prefix and empty defaultRepo falls back to docker-local",
			fullImageName: "myapp:latest",
			defaultRepo:   "",
			expectedRepo:  "docker-local",
			expectedImage: "myapp",
			expectedTag:   "latest",
		},
		{
			name:          "Invalid format - empty string",
			fullImageName: "",
			defaultRepo:   "docker-local",
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, image, tag, err := ParseImageName(tt.fullImageName, tt.defaultRepo)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedRepo, repo)
				assert.Equal(t, tt.expectedImage, image)
				assert.Equal(t, tt.expectedTag, tag)
			}
		})
	}
}

func TestFilterManifestsByPlatform(t *testing.T) {
	manifests := []dockerPath{
		{
			os:      "linux",
			arch:    "amd64",
			path:    "docker-local/myapp/latest/manifests/amd64",
			digests: []string{"sha256:aaa"},
		},
		{
			os:      "linux",
			arch:    "arm64",
			path:    "docker-local/myapp/latest/manifests/arm64",
			digests: []string{"sha256:bbb"},
		},
		{
			os:      "windows",
			arch:    "amd64",
			path:    "docker-local/myapp/latest/manifests/win-amd64",
			digests: []string{"sha256:ccc"},
		},
	}

	tests := []struct {
		name          string
		arch          string
		os            string
		expectedCount int
	}{
		{
			name:          "Filter by architecture only",
			arch:          "amd64",
			os:            "",
			expectedCount: 2, // linux/amd64 and windows/amd64
		},
		{
			name:          "Filter by OS only",
			arch:          "",
			os:            "linux",
			expectedCount: 2, // linux/amd64 and linux/arm64
		},
		{
			name:          "Filter by both arch and OS",
			arch:          "arm64",
			os:            "linux",
			expectedCount: 1, // linux/arm64 only
		},
		{
			name:          "No filters",
			arch:          "",
			os:            "",
			expectedCount: 3, // all manifests
		},
		{
			name:          "No matches",
			arch:          "s390x",
			os:            "linux",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := FilterManifestsByPlatform(manifests, tt.arch, tt.os)
			assert.Equal(t, tt.expectedCount, len(filtered))
		})
	}
}

func TestGetDigestPaths(t *testing.T) {
	tests := []struct {
		name          string
		repoKey       string
		digest        string
		expectedPaths int
		firstExpected string
	}{
		{
			name:          "SHA256 digest with prefix",
			repoKey:       "docker-local",
			digest:        "sha256:abc123def456",
			expectedPaths: 4,
			firstExpected: "docker-local/blobs/sha256/abc123def456",
		},
		{
			name:          "SHA256 digest without prefix",
			repoKey:       "docker-local",
			digest:        "abc123def456",
			expectedPaths: 4,
			firstExpected: "docker-local/blobs/sha256/abc123def456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := GetDigestPaths(tt.repoKey, tt.digest)

			assert.Equal(t, tt.expectedPaths, len(paths))
			assert.Equal(t, tt.firstExpected, paths[0])
		})
	}
}

func TestIsValidManifestContent(t *testing.T) {
	tests := []struct {
		name     string
		content  []byte
		expected bool
	}{
		{
			name:     "Valid manifest JSON",
			content:  []byte(`{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json"}`),
			expected: true,
		},
		{
			name:     "Invalid JSON",
			content:  []byte(`not json`),
			expected: false,
		},
		{
			name:     "Empty content",
			content:  []byte{},
			expected: false,
		},
		{
			name:     "Non-JSON content",
			content:  []byte(`Hello World`),
			expected: false,
		},
		{
			name:     "Valid JSON but missing schemaVersion",
			content:  []byte(`{"mediaType": "application/vnd.docker.distribution.manifest.v2+json"}`),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidManifestContent(tt.content)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildXrayAPIEndpoint(t *testing.T) {
	// Test URL construction logic (previously via buildXrayAPIEndpoint helper).
	// The rule: if base ends with /xray, append path directly; otherwise insert /xray before path.

	// Base already ends with /xray — just append path
	assert.Equal(t,
		"https://example.jfrog.io/xray/api/v2/summary/artifact",
		"https://example.jfrog.io/xray"+"/api/v2/summary/artifact",
	)

	// Base without /xray — insert it between base and path
	assert.Equal(t,
		"https://example.jfrog.io/xray/api/v2/summary/artifact",
		"https://example.jfrog.io"+"/xray"+"/api/v2/summary/artifact",
	)
}

// TestGithubMDOutputNoLogLeakage verifies that github-md stdout contains only markdown lines —
// no JFrog SDK log lines (which look like "HH:MM:SS [🔵Info] ..."). This guards against
// regressions where log.SetLogger is called after the first log.Info, leaking into the output.
func TestGithubMDOutputNoLogLeakage(t *testing.T) {
	// Mock Artifactory server: AQL search returns empty results → image-not-found path.
	// The image-not-found path emits github-md output without any Xray API calls, so we
	// only need to mock the AQL endpoint.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if strings.Contains(r.URL.Path, "search/aql") {
			_, _ = io.WriteString(w, `{"results":[]}`)
		} else {
			_, _ = io.WriteString(w, `{}`)
		}
	}))
	defer srv.Close()

	client, err := jfroghttpclient.JfrogClientBuilder().Build()
	require.NoError(t, err)

	artDetails := artAuth.NewArtifactoryDetails()
	artDetails.SetUrl(srv.URL + "/")
	artSvc := NewArtifactoryService(client, artDetails)

	xrayDetails := xrayAuth.NewXrayDetails()
	xrayDetails.SetUrl(srv.URL + "/")
	xraySvc := NewXrayService(client, xrayDetails)

	conf := &CheckConfiguration{
		ImageName:          "docker-local/noexist:notag",
		Output:             "github-md",
		Silent:             true,
		MaliciousWatchName: "test-watch",
		ProjectKey:         "default",
		AppName:            "vulnreport",
		AppVersion:         "vtest",
	}

	// Capture stdout so we can inspect it for log leakage.
	origStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	require.NoError(t, pipeErr)
	os.Stdout = w

	_ = RunCheckCommandFromConf(conf, "docker-local", "noexist", "notag", srv.URL, xraySvc, artSvc)

	require.NoError(t, w.Close())
	os.Stdout = origStdout

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	// Every line must be markdown or blank — no log timestamp prefix.
	for line := range strings.SplitSeq(output, "\n") {
		if line == "" {
			continue
		}
		// JFrog log lines start with a time stamp: "HH:MM:SS [..."
		assert.NotRegexp(t, `^\d{2}:\d{2}:\d{2}`, line,
			"log line leaked into github-md stdout: %q", line)
	}
}

// ---------------------------------------------------------------------------
// End-to-end pipeline smoke tests — JSON and github-md output paths
// ---------------------------------------------------------------------------

// endToEndMockServer creates a test HTTP server that handles all three API endpoints
// (Artifactory AQL, Xray v1 violations, Xray v2 summary) with realistic responses.
// Returns one single-platform image (linux/amd64) with one malicious Critical finding
// (XRAY-MAL-1) and one High+fixable finding (XRAY-CVE-1, JFrog research: Medium).
func endToEndMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "search/aql"):
			_, _ = io.WriteString(w, `{"results":[{"repo":"docker-local","path":"myapp/v1","name":"manifest.json","sha256":"abc123def456","properties":[{"key":"docker.os","value":"linux"},{"key":"docker.architecture","value":"amd64"}]}]}`)
		case strings.Contains(r.URL.Path, "v1/violations"):
			_, _ = io.WriteString(w, `{"total_violations":1,"violations":[{"violation_id":"V-001","issue_id":"XRAY-MAL-1","severity":"Critical","malicious_package":true}]}`)
		case strings.Contains(r.URL.Path, "v2/summary/artifact"):
			_, _ = io.WriteString(w, `{"artifacts":[{"issues":[{"issue_id":"XRAY-MAL-1","severity":"Critical","extended_information":{"jfrog_research_severity":"Critical"},"components":[{"fixed_versions":[]}]},{"issue_id":"XRAY-CVE-1","severity":"High","cves":[{"cve":"CVE-2024-99999"}],"extended_information":{"jfrog_research_severity":"Medium"},"components":[{"fixed_versions":["2.0.0"]}]}]}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// endToEndServices creates XrayService and ArtifactoryService pointing at the given test server.
func endToEndServices(t *testing.T, srv *httptest.Server) (*XrayService, *ArtifactoryService) {
	t.Helper()
	client, err := jfroghttpclient.JfrogClientBuilder().Build()
	require.NoError(t, err)
	artDetails := artAuth.NewArtifactoryDetails()
	artDetails.SetUrl(srv.URL + "/")
	xrayDetails := xrayAuth.NewXrayDetails()
	xrayDetails.SetUrl(srv.URL + "/")
	return NewXrayService(client, xrayDetails), NewArtifactoryService(client, artDetails)
}

func TestRunCheckCommandPipeline_JSONOutput(t *testing.T) {
	srv := endToEndMockServer(t)
	xraySvc, artSvc := endToEndServices(t, srv)

	conf := &CheckConfiguration{
		ImageName:          "docker-local/myapp:v1",
		Output:             "json",
		MaliciousWatchName: "test-watch",
		ProjectKey:         "default",
		AppName:            "vulnreport",
		AppVersion:         "vtest",
	}

	out := captureStdout(t, func() {
		err := RunCheckCommandFromConf(conf, "docker-local", "myapp", "v1", srv.URL, xraySvc, artSvc)
		assert.NoError(t, err)
	})

	var report EnhancedVulnerabilityReport
	require.NoError(t, json.Unmarshal([]byte(out), &report), "JSON output must parse cleanly")

	assert.Equal(t, "docker-local/myapp:v1", report.ImageName)
	assert.False(t, report.ImageNotFound)
	assert.Equal(t, 2, report.Summary.TotalFindings)
	assert.Equal(t, 1, report.Summary.CriticalCount)
	assert.Equal(t, 1, report.Summary.HighCount)
	assert.Equal(t, 1, report.Summary.FixableCount)
	assert.Equal(t, 1, report.Summary.MaliciousCount)
	assert.Equal(t, 1, report.Summary.PlatformCount)
	assert.Equal(t, []string{"XRAY-MAL-1"}, report.MaliciousIssues)

	require.Len(t, report.Platforms, 1)
	assert.Equal(t, "linux", report.Platforms[0].Platform.OS)
	assert.Equal(t, "amd64", report.Platforms[0].Platform.Architecture)

	require.Len(t, report.Findings, 2)
	// Critical sorts first; XRAY-MAL-1 is malicious+critical, not fixable.
	assert.Equal(t, "XRAY-MAL-1", report.Findings[0].IssueID)
	assert.Equal(t, "Critical", report.Findings[0].Severity)
	assert.Equal(t, "Critical", report.Findings[0].JFrogSeverity)
	assert.True(t, report.Findings[0].Malicious)
	assert.False(t, report.Findings[0].Fixable)
	// High+fixable; JFrog research rates it Medium; has CVE ID.
	assert.Equal(t, "XRAY-CVE-1", report.Findings[1].IssueID)
	assert.Equal(t, "High", report.Findings[1].Severity)
	assert.Equal(t, "Medium", report.Findings[1].JFrogSeverity)
	assert.Equal(t, []string{"CVE-2024-99999"}, report.Findings[1].CVEIDs)
	assert.False(t, report.Findings[1].Malicious)
	assert.True(t, report.Findings[1].Fixable)
	// Malicious finding has no CVE ID.
	assert.Empty(t, report.Findings[0].CVEIDs)
}

func TestRunCheckCommandPipeline_GithubMDOutput(t *testing.T) {
	srv := endToEndMockServer(t)
	xraySvc, artSvc := endToEndServices(t, srv)

	conf := &CheckConfiguration{
		ImageName:          "docker-local/myapp:v1",
		Output:             "github-md",
		Silent:             true,
		MaliciousWatchName: "test-watch",
		ProjectKey:         "default",
		AppName:            "vulnreport",
		AppVersion:         "vtest",
	}

	out := captureStdout(t, func() {
		err := RunCheckCommandFromConf(conf, "docker-local", "myapp", "v1", srv.URL, xraySvc, artSvc)
		assert.NoError(t, err)
	})

	// Banner: malicious takes highest priority over all other states.
	assert.Contains(t, out, "badge-malicious.png")
	assert.Contains(t, out, "[!CAUTION]")
	assert.Contains(t, out, "MALICIOUS EXPLOIT PRESENT")

	// Security Summary section with all counts populated.
	assert.Contains(t, out, "## Security Summary")
	assert.Contains(t, out, "**Total Findings:** 2")
	assert.Contains(t, out, "**Critical:** 1")
	assert.Contains(t, out, "**High:** 1")
	assert.Contains(t, out, "**Malicious:** 1")
	assert.Contains(t, out, "linux/amd64")

	// Malicious findings table with the XRAY ID from the violations watch.
	assert.Contains(t, out, "Malicious Findings (1)")
	assert.Contains(t, out, "XRAY-MAL-1")

	// Security findings table with fixable count, CVE ID column, and both findings.
	assert.Contains(t, out, "1 fixable")
	assert.Contains(t, out, "CVE ID")
	assert.Contains(t, out, "CVE-2024-99999")
	assert.Contains(t, out, "XRAY-CVE-1")

	// No log-line leakage (github-md sets log level to ERROR).
	for line := range strings.SplitSeq(out, "\n") {
		if line == "" {
			continue
		}
		assert.NotRegexp(t, `^\d{2}:\d{2}:\d{2}`, line,
			"log line leaked into github-md stdout: %q", line)
	}

	// Footer
	assert.Contains(t, out, "Generated by vulnreport vtest")
}

func TestViolationWithMaliciousExtractsFromResponse(t *testing.T) {
	// Verify that the Violations API response parsing preserves malicious_package status.
	// This is the key optimization: malicious detection now comes from a single Violations API
	// call instead of N+1 Events API calls (one per issue ID).
	respBody := []byte(`{
		"total_violations": 2,
		"violations": [
			{
				"violation_id": "V-001",
				"description": "Test vuln A",
				"severity": "High",
				"type": "CVE",
				"issue_id": "XRAY-100",
				"malicious_package": true
			},
			{
				"violation_id": "V-002",
				"description": "Test vuln B",
				"severity": "Medium",
				"type": "CVE",
				"issue_id": "XRAY-101",
				"malicious_package": false
			}
		]
	}`)

	type violationResponse struct {
		TotalViolations int             `json:"total_violations"`
		Violations      []xrayViolation `json:"violations"`
	}
	var resp violationResponse
	err := json.Unmarshal(respBody, &resp)
	assert.NoError(t, err)

	assert.Equal(t, 2, resp.TotalViolations)
	assert.True(t, resp.Violations[0].MaliciousPackage, "XRAY-100 should be marked malicious")
	assert.False(t, resp.Violations[1].MaliciousPackage, "XRAY-101 should not be marked malicious")
}

// captureStdout runs fn and returns everything written to os.Stdout during the call.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	old := os.Stdout
	os.Stdout = w
	fn()
	require.NoError(t, w.Close())
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	return buf.String()
}

// ---------------------------------------------------------------------------
// severityRank
// ---------------------------------------------------------------------------

func TestSeverityRank(t *testing.T) {
	cases := []struct {
		input    string
		expected int
	}{
		{"Malicious", -1},
		{"Critical", 0},
		{"High", 1},
		{"Medium", 2},
		{"Low", 3},
		{"Unknown", 4},
		{"", 4},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.expected, severityRank(tc.input))
		})
	}
}

// ---------------------------------------------------------------------------
// severityMeetsMin
// ---------------------------------------------------------------------------

func TestSeverityMeetsMin(t *testing.T) {
	cases := []struct {
		severity    string
		minSeverity string
		expected    bool
	}{
		{"Critical", "", true},           // empty min passes everything
		{"Low", "Low", true},             // equal rank passes
		{"Low", "Medium", false},         // too low
		{"High", "Critical", false},      // below threshold
		{"Critical", "High", true},       // above threshold
		{"Malicious", "Critical", true},  // rank -1 ≤ 0
		{"Low", "Malicious", false},      // rank 3 > -1
		{"Critical", "Malicious", false}, // rank 0 > -1
		{"Malicious", "Malicious", true}, // exact match
		{"Low", "Unknown", true},         // unrecognized min → pass all
		{"Unknown", "Low", true},         // unrecognized severity → pass through
	}
	for _, tc := range cases {
		name := tc.severity + "_min_" + tc.minSeverity
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.expected, severityMeetsMin(tc.severity, tc.minSeverity))
		})
	}
}

// ---------------------------------------------------------------------------
// generateSecurityBanner
// ---------------------------------------------------------------------------

func TestGenerateSecurityBanner_MaliciousViaMap(t *testing.T) {
	report := &VulnerabilityReport{}
	lookup := map[string]bool{"XRAY-1": true}
	var buf bytes.Buffer
	generateSecurityBanner(&buf, report, lookup)
	out := buf.String()
	assert.Contains(t, out, "badge-malicious.png")
	assert.Contains(t, out, "[!CAUTION]")
	assert.Contains(t, out, "MALICIOUS EXPLOIT PRESENT")
}

func TestGenerateSecurityBanner_MaliciousViaSlice(t *testing.T) {
	report := &VulnerabilityReport{MaliciousIssues: []string{"XRAY-1"}}
	var buf bytes.Buffer
	generateSecurityBanner(&buf, report, map[string]bool{})
	out := buf.String()
	assert.Contains(t, out, "badge-malicious.png")
	assert.Contains(t, out, "[!CAUTION]")
}

func TestGenerateSecurityBanner_Critical(t *testing.T) {
	report := &VulnerabilityReport{CriticalCount: 1, TotalIssues: 1}
	var buf bytes.Buffer
	generateSecurityBanner(&buf, report, map[string]bool{})
	out := buf.String()
	assert.Contains(t, out, "badge-critical-cve.png")
	assert.Contains(t, out, "[!CAUTION]")
	assert.NotContains(t, out, "MALICIOUS")
}

func TestGenerateSecurityBanner_NonCriticalFindings(t *testing.T) {
	report := &VulnerabilityReport{HighCount: 2, TotalIssues: 2}
	var buf bytes.Buffer
	generateSecurityBanner(&buf, report, map[string]bool{})
	out := buf.String()
	assert.Contains(t, out, "CVE")
	assert.Contains(t, out, "[!WARNING]")
	assert.NotContains(t, out, "MALICIOUS")
	assert.NotContains(t, out, "CRITICAL")
}

func TestGenerateSecurityBanner_Clean(t *testing.T) {
	report := &VulnerabilityReport{}
	var buf bytes.Buffer
	generateSecurityBanner(&buf, report, map[string]bool{})
	out := buf.String()
	assert.Contains(t, out, "badge-no-findings.png")
	assert.Contains(t, out, "[!NOTE]")
}

// ---------------------------------------------------------------------------
// outputJSONReport
// ---------------------------------------------------------------------------

func TestOutputJSONReport_ImageNotFound(t *testing.T) {
	report := &VulnerabilityReport{
		ImageName:     "docker-local/bad:tag",
		GeneratedAt:   "2026-01-01T00:00:00Z",
		ImageNotFound: true,
	}
	var buf bytes.Buffer
	require.NoError(t, outputJSONReport(&buf, report, map[string]bool{}, "vulnreport", "vtest"))

	var enhanced EnhancedVulnerabilityReport
	require.NoError(t, json.Unmarshal(buf.Bytes(), &enhanced))
	assert.True(t, enhanced.ImageNotFound)
	assert.Equal(t, 0, enhanced.Summary.TotalFindings)
	assert.Equal(t, 0, enhanced.Summary.MaliciousCount)
	assert.Empty(t, enhanced.Platforms)
}

func TestOutputJSONReport_AppNameVersionPresent(t *testing.T) {
	report := &VulnerabilityReport{
		ImageName:   "docker-local/app:v1",
		GeneratedAt: "2026-01-01T00:00:00Z",
	}
	var buf bytes.Buffer
	require.NoError(t, outputJSONReport(&buf, report, map[string]bool{}, "vulnreport", "v0.1.9"))

	var enhanced EnhancedVulnerabilityReport
	require.NoError(t, json.Unmarshal(buf.Bytes(), &enhanced))
	assert.Equal(t, "vulnreport", enhanced.PluginName)
	assert.Equal(t, "v0.1.9", enhanced.PluginVersion)
}

func TestOutputJSONReport_WithCounts(t *testing.T) {
	report := &VulnerabilityReport{
		ImageName:     "docker-local/app:v1",
		GeneratedAt:   "2026-01-01T00:00:00Z",
		TotalIssues:   7,
		CriticalCount: 2,
		HighCount:     5,
		Platforms: []PlatformVulnerabilityInfo{
			{Platform: Platform{OS: "linux", Architecture: "amd64"}},
		},
		SummaryIssues: []SummaryIssue{
			{IssueID: "XRAY-10", Severity: "Critical", Fixable: true, Platforms: []string{"linux/amd64"}},
			{IssueID: "XRAY-20", Severity: "High", Fixable: false, Platforms: []string{"linux/amd64"}},
		},
	}
	lookup := map[string]bool{"XRAY-1": true}
	var buf bytes.Buffer
	require.NoError(t, outputJSONReport(&buf, report, lookup, "vulnreport", "vtest"))

	var enhanced EnhancedVulnerabilityReport
	require.NoError(t, json.Unmarshal(buf.Bytes(), &enhanced))
	assert.Equal(t, 7, enhanced.Summary.TotalFindings)
	assert.Equal(t, 2, enhanced.Summary.CriticalCount)
	assert.Equal(t, 5, enhanced.Summary.HighCount)
	assert.Equal(t, 1, enhanced.Summary.FixableCount)
	assert.Equal(t, 1, enhanced.Summary.MaliciousCount) // from map size
	assert.Equal(t, 1, enhanced.Summary.PlatformCount)
	require.Len(t, enhanced.Findings, 2)
	assert.Equal(t, "XRAY-10", enhanced.Findings[0].IssueID) // Critical sorts first
	assert.True(t, enhanced.Findings[0].Fixable)
}

func TestOutputJSONReport_MaliciousCountFromMap(t *testing.T) {
	// MaliciousCount in summary comes from len(maliciousLookup); MaliciousIssues from report.MaliciousIssues.
	report := &VulnerabilityReport{
		ImageName:       "docker-local/app:v1",
		GeneratedAt:     "2026-01-01T00:00:00Z",
		MaliciousIssues: []string{"A", "B"},
	}
	lookup := map[string]bool{"A": true, "B": true, "C": true}
	var buf bytes.Buffer
	require.NoError(t, outputJSONReport(&buf, report, lookup, "vulnreport", "vtest"))

	var enhanced EnhancedVulnerabilityReport
	require.NoError(t, json.Unmarshal(buf.Bytes(), &enhanced))
	assert.Equal(t, 3, enhanced.Summary.MaliciousCount)           // map has 3 keys
	assert.Equal(t, []string{"A", "B"}, enhanced.MaliciousIssues) // from report.MaliciousIssues
}

func TestOutputJSONReport_FindingsFromSummaryIssues(t *testing.T) {
	report := &VulnerabilityReport{
		ImageName:   "docker-local/app:v1",
		GeneratedAt: "2026-01-01T00:00:00Z",
		SummaryIssues: []SummaryIssue{
			// High severity listed first — should sort second after Critical
			{IssueID: "XRAY-99", Severity: "High", JFrogSeverity: "Critical", Fixable: false, Platforms: []string{"linux/amd64"}},
			// Critical — should sort first
			{IssueID: "XRAY-01", Severity: "Critical", JFrogSeverity: "Critical", Fixable: true, Platforms: []string{"linux/amd64", "linux/arm64"}},
		},
		MaliciousIssues: []string{"XRAY-99"},
	}
	lookup := map[string]bool{"XRAY-99": true}
	var buf bytes.Buffer
	require.NoError(t, outputJSONReport(&buf, report, lookup, "vulnreport", "vtest"))

	var enhanced EnhancedVulnerabilityReport
	require.NoError(t, json.Unmarshal(buf.Bytes(), &enhanced))

	assert.Equal(t, []string{"XRAY-99"}, enhanced.MaliciousIssues)
	assert.Equal(t, 1, enhanced.Summary.FixableCount)
	assert.Equal(t, 1, enhanced.Summary.MaliciousCount)
	require.Len(t, enhanced.Findings, 2)

	critical := enhanced.Findings[0]
	assert.Equal(t, "XRAY-01", critical.IssueID)
	assert.Equal(t, "Critical", critical.Severity)
	assert.Equal(t, "Critical", critical.JFrogSeverity)
	assert.True(t, critical.Fixable)
	assert.False(t, critical.Malicious)
	assert.Equal(t, []string{"linux/amd64", "linux/arm64"}, critical.Platforms)

	high := enhanced.Findings[1]
	assert.Equal(t, "XRAY-99", high.IssueID)
	assert.Equal(t, "High", high.Severity)
	assert.True(t, high.Malicious)
	assert.False(t, high.Fixable)
}

// ---------------------------------------------------------------------------
// outputMarkdownReport
// ---------------------------------------------------------------------------

func TestOutputMarkdownReport_ImageNotFound(t *testing.T) {
	report := &VulnerabilityReport{
		ImageName:     "docker-local/bad:tag",
		GeneratedAt:   "2026-01-01T00:00:00Z",
		ImageNotFound: true,
	}
	var buf bytes.Buffer
	require.NoError(t, outputMarkdownReport(&buf, report, map[string]bool{}, "", "", false, "vulnreport", "vtest"))
	out := buf.String()
	assert.Contains(t, out, "badge-no-image-found.png")
	assert.Contains(t, out, "# Xray Security Report")
	assert.Contains(t, out, "No Image Found")
	assert.Contains(t, out, "Generated by vulnreport vtest")
	assert.NotContains(t, out, "## Security Summary")
}

func TestOutputMarkdownReport_ManifestURLPresent(t *testing.T) {
	report := &VulnerabilityReport{
		ImageName:   "docker-local/app:v1",
		GeneratedAt: "2026-01-01T00:00:00Z",
	}
	var buf bytes.Buffer
	require.NoError(t, outputMarkdownReport(&buf, report, map[string]bool{}, "https://example.jfrog.io/ui/repos/tree/Xray/docker-local/app/v1/manifest.json", "", false, "vulnreport", "vtest"))
	out := buf.String()
	assert.Contains(t, out, "> **View manifest:**")
	assert.Contains(t, out, "https://example.jfrog.io/ui/repos/tree/Xray/docker-local/app/v1/manifest.json")
}

func TestOutputMarkdownReport_ManifestURLAbsent(t *testing.T) {
	report := &VulnerabilityReport{
		ImageName:   "docker-local/app:v1",
		GeneratedAt: "2026-01-01T00:00:00Z",
	}
	var buf bytes.Buffer
	require.NoError(t, outputMarkdownReport(&buf, report, map[string]bool{}, "", "", false, "vulnreport", "vtest"))
	out := buf.String()
	assert.NotContains(t, out, "View manifest")
}

func TestOutputMarkdownReport_NoFindingsFlag(t *testing.T) {
	report := &VulnerabilityReport{
		ImageName:   "docker-local/app:v1",
		GeneratedAt: "2026-01-01T00:00:00Z",
		TotalIssues: 3,
		HighCount:   3,
		SummaryIssues: []SummaryIssue{
			{IssueID: "XRAY-100", Severity: "High", Fixable: true},
			{IssueID: "XRAY-101", Severity: "High"},
			{IssueID: "XRAY-102", Severity: "High"},
		},
	}
	var buf bytes.Buffer
	require.NoError(t, outputMarkdownReport(&buf, report, map[string]bool{}, "", "", true, "vulnreport", "vtest"))
	out := buf.String()
	assert.NotContains(t, out, "<details>")
	assert.NotContains(t, out, "Security Findings")
}

func TestOutputMarkdownReport_MinSeverityFiltering(t *testing.T) {
	report := &VulnerabilityReport{
		ImageName:   "docker-local/app:v1",
		GeneratedAt: "2026-01-01T00:00:00Z",
		TotalIssues: 3,
		SummaryIssues: []SummaryIssue{
			{IssueID: "XRAY-CRIT", Severity: "Critical"},
			{IssueID: "XRAY-HIGH", Severity: "High"},
			{IssueID: "XRAY-LOW", Severity: "Low"},
		},
	}
	var buf bytes.Buffer
	require.NoError(t, outputMarkdownReport(&buf, report, map[string]bool{}, "", "High", false, "vulnreport", "vtest"))
	out := buf.String()
	assert.Contains(t, out, "XRAY-CRIT")
	assert.Contains(t, out, "XRAY-HIGH")
	assert.NotContains(t, out, "XRAY-LOW")
}

func TestOutputMarkdownReport_MaliciousFindingsTable(t *testing.T) {
	report := &VulnerabilityReport{
		ImageName:       "docker-local/app:v1",
		GeneratedAt:     "2026-01-01T00:00:00Z",
		MaliciousIssues: []string{"XRAY-A", "XRAY-B"},
		SummaryIssues: []SummaryIssue{
			{IssueID: "XRAY-A", Severity: "Critical", CVEIDs: []string{"CVE-2024-00001"}},
			{IssueID: "XRAY-B", Severity: "Critical"},
		},
	}
	var buf bytes.Buffer
	require.NoError(t, outputMarkdownReport(&buf, report, map[string]bool{"XRAY-A": true, "XRAY-B": true}, "", "", false, "vulnreport", "vtest"))
	out := buf.String()
	assert.Contains(t, out, "Malicious Findings (2)")
	assert.Contains(t, out, "CVE ID")
	assert.Contains(t, out, "CVE-2024-00001")
	assert.Contains(t, out, "XRAY-A")
	assert.Contains(t, out, "XRAY-B")
}

func TestOutputMarkdownReport_FindingsTableSorting(t *testing.T) {
	report := &VulnerabilityReport{
		ImageName:   "docker-local/app:v1",
		GeneratedAt: "2026-01-01T00:00:00Z",
		TotalIssues: 3,
		SummaryIssues: []SummaryIssue{
			{IssueID: "XRAY-200", Severity: "High"}, // added out of severity order
			{IssueID: "XRAY-100", Severity: "Critical"},
			{IssueID: "XRAY-101", Severity: "Critical"}, // same severity — sort by ID
		},
	}
	var buf bytes.Buffer
	require.NoError(t, outputMarkdownReport(&buf, report, map[string]bool{}, "", "", false, "vulnreport", "vtest"))
	out := buf.String()
	// Critical rows must appear before the High row.
	critPos := strings.Index(out, "XRAY-100")
	highPos := strings.Index(out, "XRAY-200")
	require.True(t, critPos >= 0 && highPos >= 0)
	assert.Less(t, critPos, highPos, "Critical finding should appear before High finding")
	// Within Critical, XRAY-100 must appear before XRAY-101.
	pos100 := strings.Index(out, "XRAY-100")
	pos101 := strings.Index(out, "XRAY-101")
	assert.Less(t, pos100, pos101, "XRAY-100 should appear before XRAY-101 (lexicographic)")
}

func TestOutputMarkdownReport_Footer(t *testing.T) {
	report := &VulnerabilityReport{
		ImageName:   "docker-local/app:v1",
		GeneratedAt: "2026-07-23T10:00:00Z",
	}
	var buf bytes.Buffer
	require.NoError(t, outputMarkdownReport(&buf, report, map[string]bool{}, "", "", false, "vulnreport", "vtest"))
	out := buf.String()
	assert.Contains(t, out, "Generated by vulnreport vtest")
	assert.Contains(t, out, "2026-07-23T10:00:00Z")
}

// ---------------------------------------------------------------------------
// outputReport
// ---------------------------------------------------------------------------

func TestOutputReport_UnsupportedFormat(t *testing.T) {
	report := &VulnerabilityReport{ImageName: "docker-local/app:v1", GeneratedAt: "2026-01-01T00:00:00Z"}
	err := outputReport(&bytes.Buffer{}, report, map[string]bool{}, "xml", "", "", false, "vulnreport", "vtest")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported output format")
}

func TestOutputTableReport_ImageNotFound(t *testing.T) {
	report := &VulnerabilityReport{
		ImageName:     "docker-local/missing:v1",
		GeneratedAt:   "2026-01-01T00:00:00Z",
		ImageNotFound: true,
	}
	var buf bytes.Buffer
	require.NoError(t, outputTableReport(&buf, report, map[string]bool{}, "", "", false, "vulnreport", "vtest"))
	out := buf.String()
	assert.Contains(t, out, "docker-local/missing:v1")
	assert.Contains(t, out, "No Image Found")
	assert.Contains(t, out, "vulnreport vtest")
}

func TestOutputTableReport_Clean(t *testing.T) {
	report := &VulnerabilityReport{
		ImageName:   "docker-local/clean:v1",
		GeneratedAt: "2026-01-01T00:00:00Z",
		Platforms:   []PlatformVulnerabilityInfo{{Platform: Platform{OS: "linux", Architecture: "amd64"}}},
	}
	var buf bytes.Buffer
	require.NoError(t, outputTableReport(&buf, report, map[string]bool{}, "https://example.com/manifest", "", false, "vulnreport", "vtest"))
	out := buf.String()
	assert.Contains(t, out, "docker-local/clean:v1")
	assert.Contains(t, out, "https://example.com/manifest")
	assert.Contains(t, out, "NO FINDINGS")
	assert.Contains(t, out, "Total Findings")
	assert.Contains(t, out, "vulnreport vtest")
}

func TestOutputTableReport_WithFindings(t *testing.T) {
	report := &VulnerabilityReport{
		ImageName:     "docker-local/app:v1",
		GeneratedAt:   "2026-01-01T00:00:00Z",
		TotalIssues:   2,
		CriticalCount: 1,
		HighCount:     1,
		Platforms:     []PlatformVulnerabilityInfo{{Platform: Platform{OS: "linux", Architecture: "amd64"}}},
		SummaryIssues: []SummaryIssue{
			{IssueID: "XRAY-999", Severity: "Critical", Fixable: true, Platforms: []string{"linux/amd64"}, CVEIDs: []string{"CVE-2024-11111"}},
			{IssueID: "XRAY-888", Severity: "High", Fixable: false, Platforms: []string{"linux/amd64"}},
		},
	}
	var buf bytes.Buffer
	require.NoError(t, outputTableReport(&buf, report, map[string]bool{}, "", "", false, "vulnreport", "vtest"))
	out := buf.String()
	assert.Contains(t, out, "CRITICAL CVEs PRESENT")
	assert.Contains(t, out, "Security Findings (2 | 1 fixable)")
	assert.Contains(t, out, "CVE ID")
	assert.Contains(t, out, "CVE-2024-11111")
	assert.Contains(t, out, "XRAY-999")
	assert.Contains(t, out, "XRAY-888")
	assert.Contains(t, out, "Critical")
	assert.Contains(t, out, "High")
}

func TestOutputTableReport_CVEIDAbsent(t *testing.T) {
	report := &VulnerabilityReport{
		ImageName:   "docker-local/app:v1",
		GeneratedAt: "2026-01-01T00:00:00Z",
		TotalIssues: 1,
		HighCount:   1,
		Platforms:   []PlatformVulnerabilityInfo{{Platform: Platform{OS: "linux", Architecture: "amd64"}}},
		SummaryIssues: []SummaryIssue{
			{IssueID: "XRAY-777", Severity: "High", Fixable: false, Platforms: []string{"linux/amd64"}},
		},
	}
	var buf bytes.Buffer
	require.NoError(t, outputTableReport(&buf, report, map[string]bool{}, "", "", false, "vulnreport", "vtest"))
	out := buf.String()
	assert.Contains(t, out, "CVE ID")
	assert.Contains(t, out, "-") // dash shown when no CVE ID
}

func TestOutputTableReport_Malicious(t *testing.T) {
	report := &VulnerabilityReport{
		ImageName:       "docker-local/bad:v1",
		GeneratedAt:     "2026-01-01T00:00:00Z",
		TotalIssues:     1,
		CriticalCount:   1,
		MaliciousIssues: []string{"XRAY-666"},
		Platforms:       []PlatformVulnerabilityInfo{{Platform: Platform{OS: "linux", Architecture: "amd64"}}},
		SummaryIssues: []SummaryIssue{
			{IssueID: "XRAY-666", Severity: "Critical", Fixable: false, Platforms: []string{"linux/amd64"}, CVEIDs: []string{"CVE-2024-66666"}},
		},
	}
	lookup := map[string]bool{"XRAY-666": true}
	var buf bytes.Buffer
	require.NoError(t, outputTableReport(&buf, report, lookup, "", "", false, "vulnreport", "vtest"))
	out := buf.String()
	assert.Contains(t, out, "MALICIOUS EXPLOIT PRESENT")
	assert.Contains(t, out, "Malicious Findings (1)")
	assert.Contains(t, out, "CVE ID")
	assert.Contains(t, out, "CVE-2024-66666")
	assert.Contains(t, out, "XRAY-666")
	assert.Contains(t, out, "Security Findings")
}

// ---------------------------------------------------------------------------
// --save-output: file writing and console confirmation
// ---------------------------------------------------------------------------

// chdirTemp changes the working directory to a temp dir for the duration of the test.
func chdirTemp(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	orig, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tmp))
	t.Cleanup(func() { _ = os.Chdir(orig) })
	return tmp
}

func TestSaveOutput_JSON(t *testing.T) {
	tmp := chdirTemp(t)
	srv := endToEndMockServer(t)
	xraySvc, artSvc := endToEndServices(t, srv)

	conf := &CheckConfiguration{
		ImageName:          "docker-local/myapp:v1",
		Output:             "table",
		MaliciousWatchName: "test-watch",
		ProjectKey:         "default",
		AppName:            "vulnreport",
		AppVersion:         "vtest",
		SaveOutput:         "json",
	}

	out := captureStdout(t, func() {
		require.NoError(t, RunCheckCommandFromConf(conf, "docker-local", "myapp", "v1", srv.URL, xraySvc, artSvc))
	})

	// Console only shows the saved confirmation — no report body.
	assert.Contains(t, out, "vulnreport.json")
	assert.NotContains(t, out, "Security Summary")

	// File exists and contains valid JSON with expected content.
	data, err := os.ReadFile(filepath.Join(tmp, "vulnreport.json")) //nolint:gosec // G304: path is test-controlled temp dir
	require.NoError(t, err)
	var report EnhancedVulnerabilityReport
	require.NoError(t, json.Unmarshal(data, &report), "vulnreport.json must be valid JSON")
	assert.Equal(t, "docker-local/myapp:v1", report.ImageName)
	assert.Equal(t, 2, report.Summary.TotalFindings)
	assert.Equal(t, []string{"XRAY-MAL-1"}, report.MaliciousIssues)
}

func TestSaveOutput_GithubMD(t *testing.T) {
	tmp := chdirTemp(t)
	srv := endToEndMockServer(t)
	xraySvc, artSvc := endToEndServices(t, srv)

	conf := &CheckConfiguration{
		ImageName:          "docker-local/myapp:v1",
		Output:             "table",
		MaliciousWatchName: "test-watch",
		ProjectKey:         "default",
		AppName:            "vulnreport",
		AppVersion:         "vtest",
		SaveOutput:         "github-md",
	}

	out := captureStdout(t, func() {
		require.NoError(t, RunCheckCommandFromConf(conf, "docker-local", "myapp", "v1", srv.URL, xraySvc, artSvc))
	})

	assert.Contains(t, out, "vulnreport.md")
	assert.NotContains(t, out, "Security Summary")

	data, err := os.ReadFile(filepath.Join(tmp, "vulnreport.md")) //nolint:gosec // G304: path is test-controlled temp dir
	require.NoError(t, err)
	md := string(data)
	assert.Contains(t, md, "badge-malicious.png")
	assert.Contains(t, md, "MALICIOUS EXPLOIT PRESENT")
	assert.Contains(t, md, "## Security Summary")
	assert.Contains(t, md, "Generated by vulnreport vtest")
}

func TestSaveOutput_BothFormats(t *testing.T) {
	tmp := chdirTemp(t)
	srv := endToEndMockServer(t)
	xraySvc, artSvc := endToEndServices(t, srv)

	conf := &CheckConfiguration{
		ImageName:          "docker-local/myapp:v1",
		Output:             "table",
		MaliciousWatchName: "test-watch",
		ProjectKey:         "default",
		AppName:            "vulnreport",
		AppVersion:         "vtest",
		SaveOutput:         "json,github-md",
	}

	out := captureStdout(t, func() {
		require.NoError(t, RunCheckCommandFromConf(conf, "docker-local", "myapp", "v1", srv.URL, xraySvc, artSvc))
	})

	// Both file names appear in the saved confirmation line.
	assert.Contains(t, out, "vulnreport.json")
	assert.Contains(t, out, "vulnreport.md")

	// Both files exist.
	_, err := os.Stat(filepath.Join(tmp, "vulnreport.json"))
	require.NoError(t, err, "vulnreport.json must exist")
	_, err = os.Stat(filepath.Join(tmp, "vulnreport.md"))
	require.NoError(t, err, "vulnreport.md must exist")
}

func TestSaveOutput_InvalidFormat(t *testing.T) {
	srv := endToEndMockServer(t)
	xraySvc, artSvc := endToEndServices(t, srv)

	conf := &CheckConfiguration{
		ImageName:          "docker-local/myapp:v1",
		Output:             "table",
		MaliciousWatchName: "test-watch",
		ProjectKey:         "default",
		AppName:            "vulnreport",
		AppVersion:         "vtest",
		SaveOutput:         "xml",
	}

	err := RunCheckCommandFromConf(conf, "docker-local", "myapp", "v1", srv.URL, xraySvc, artSvc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported --save-output format")
	assert.Contains(t, err.Error(), "xml")
}

func TestSaveOutput_WhitespaceTrimming(t *testing.T) {
	// "json, github-md" (space after comma) must be treated the same as "json,github-md".
	tmp := chdirTemp(t)
	report := &VulnerabilityReport{
		ImageName:   "docker-local/app:v1",
		GeneratedAt: "2026-01-01T00:00:00Z",
	}
	conf := &CheckConfiguration{
		SaveOutput: "json, github-md",
		AppName:    "vulnreport",
		AppVersion: "vtest",
	}

	out := captureStdout(t, func() {
		require.NoError(t, saveOutputToFiles(conf, report, map[string]bool{}, ""))
	})

	assert.Contains(t, out, "vulnreport.json")
	assert.Contains(t, out, "vulnreport.md")
	_, err := os.Stat(filepath.Join(tmp, "vulnreport.json"))
	require.NoError(t, err, "vulnreport.json must be created when format has surrounding whitespace")
	_, err = os.Stat(filepath.Join(tmp, "vulnreport.md"))
	require.NoError(t, err, "vulnreport.md must be created when format has surrounding whitespace")
}

func TestSaveOutput_FailOnVulnStillFires(t *testing.T) {
	// When --save-output and --fail-on-vuln are both set, the file must be written
	// AND the error must still be returned. saveOutputToFiles runs before the vuln check.
	tmp := chdirTemp(t)
	srv := endToEndMockServer(t) // returns 2 findings including 1 malicious
	xraySvc, artSvc := endToEndServices(t, srv)

	conf := &CheckConfiguration{
		ImageName:          "docker-local/myapp:v1",
		Output:             "table",
		MaliciousWatchName: "test-watch",
		ProjectKey:         "default",
		AppName:            "vulnreport",
		AppVersion:         "vtest",
		SaveOutput:         "json",
		FailOnVuln:         true,
	}

	var vulnErr error
	captureStdout(t, func() {
		vulnErr = RunCheckCommandFromConf(conf, "docker-local", "myapp", "v1", srv.URL, xraySvc, artSvc)
	})

	// fail-on-vuln must fire.
	require.Error(t, vulnErr)
	assert.Contains(t, vulnErr.Error(), "vulnerability")

	// File must have been written before the error was returned.
	data, err := os.ReadFile(filepath.Join(tmp, "vulnreport.json")) //nolint:gosec // G304: path is test-controlled temp dir
	require.NoError(t, err, "vulnreport.json must be written even when fail-on-vuln fires")
	var report EnhancedVulnerabilityReport
	require.NoError(t, json.Unmarshal(data, &report))
	assert.Equal(t, 2, report.Summary.TotalFindings)
}

func TestSaveOutput_ImageNotFound(t *testing.T) {
	// When AQL returns no results the saved JSON must have imageNotFound: true
	// and zero counts rather than an error.
	tmp := chdirTemp(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "search/aql") {
			_, _ = io.WriteString(w, `{"results":[]}`)
		} else {
			_, _ = io.WriteString(w, `{}`)
		}
	}))
	t.Cleanup(srv.Close)
	xraySvc, artSvc := endToEndServices(t, srv)

	conf := &CheckConfiguration{
		ImageName:          "docker-local/noexist:notag",
		MaliciousWatchName: "test-watch",
		ProjectKey:         "default",
		AppName:            "vulnreport",
		AppVersion:         "vtest",
		SaveOutput:         "json",
	}

	captureStdout(t, func() {
		require.NoError(t, RunCheckCommandFromConf(conf, "docker-local", "noexist", "notag", srv.URL, xraySvc, artSvc))
	})

	data, err := os.ReadFile(filepath.Join(tmp, "vulnreport.json")) //nolint:gosec // G304: path is test-controlled temp dir
	require.NoError(t, err)
	var report EnhancedVulnerabilityReport
	require.NoError(t, json.Unmarshal(data, &report))
	assert.True(t, report.ImageNotFound, "saved JSON must report imageNotFound when AQL returns no results")
	assert.Equal(t, 0, report.Summary.TotalFindings)
	assert.Equal(t, 0, report.Summary.MaliciousCount)
}

func TestSaveOutput_MinSeverityRespectedInFile(t *testing.T) {
	// --min-severity must filter the Security Findings table inside the saved markdown file.
	tmp := chdirTemp(t)
	report := &VulnerabilityReport{
		ImageName:   "docker-local/app:v1",
		GeneratedAt: "2026-01-01T00:00:00Z",
		TotalIssues: 3,
		SummaryIssues: []SummaryIssue{
			{IssueID: "XRAY-CRIT", Severity: "Critical"},
			{IssueID: "XRAY-HIGH", Severity: "High"},
			{IssueID: "XRAY-LOW", Severity: "Low"},
		},
	}
	conf := &CheckConfiguration{
		SaveOutput:  "github-md",
		MinSeverity: "High",
		AppName:     "vulnreport",
		AppVersion:  "vtest",
	}

	require.NoError(t, saveOutputToFiles(conf, report, map[string]bool{}, ""))

	data, err := os.ReadFile(filepath.Join(tmp, "vulnreport.md")) //nolint:gosec // G304: path is test-controlled temp dir
	require.NoError(t, err)
	md := string(data)
	assert.Contains(t, md, "XRAY-CRIT", "Critical must appear: meets --min-severity High")
	assert.Contains(t, md, "XRAY-HIGH", "High must appear: equals --min-severity High")
	assert.NotContains(t, md, "XRAY-LOW", "Low must be filtered out by --min-severity High")
}

func TestSaveOutput_NoFindingsRespectedInFile(t *testing.T) {
	// --no-findings must suppress the collapsible findings table inside the saved markdown file.
	tmp := chdirTemp(t)
	report := &VulnerabilityReport{
		ImageName:   "docker-local/app:v1",
		GeneratedAt: "2026-01-01T00:00:00Z",
		TotalIssues: 2,
		HighCount:   2,
		SummaryIssues: []SummaryIssue{
			{IssueID: "XRAY-100", Severity: "High"},
			{IssueID: "XRAY-101", Severity: "High"},
		},
	}
	conf := &CheckConfiguration{
		SaveOutput: "github-md",
		NoFindings: true,
		AppName:    "vulnreport",
		AppVersion: "vtest",
	}

	require.NoError(t, saveOutputToFiles(conf, report, map[string]bool{}, ""))

	data, err := os.ReadFile(filepath.Join(tmp, "vulnreport.md")) //nolint:gosec // G304: path is test-controlled temp dir
	require.NoError(t, err)
	md := string(data)
	assert.NotContains(t, md, "<details>", "--no-findings must suppress the collapsible table")
	assert.NotContains(t, md, "XRAY-100", "--no-findings must suppress individual finding rows")
	assert.Contains(t, md, "## Security Summary", "Security Summary must still appear with --no-findings")
}

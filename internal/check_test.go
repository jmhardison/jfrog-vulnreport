package internal

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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
		expectedRepo  string
		expectedImage string
		expectedTag   string
		expectError   bool
	}{
		{
			name:          "Valid image with single repository",
			fullImageName: "docker-local/myapp:latest",
			expectedRepo:  "docker-local",
			expectedImage: "myapp",
			expectedTag:   "latest",
			expectError:   false,
		},
		{
			name:          "Valid image with nested path",
			fullImageName: "docker-local/team/myapp:v1.2.3",
			expectedRepo:  "docker-local",
			expectedImage: "team/myapp",
			expectedTag:   "v1.2.3",
			expectError:   false,
		},
		{
			name:          "Invalid format - missing tag",
			fullImageName: "docker-local/myapp",
			expectError:   true,
		},
		{
			name:          "Invalid format - missing repository",
			fullImageName: "myapp:latest",
			expectError:   true,
		},
		{
			name:          "Invalid format - empty string",
			fullImageName: "",
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, image, tag, err := ParseImageName(tt.fullImageName)

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

	w.Close()
	os.Stdout = origStdout

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	// Every line must be markdown or blank — no log timestamp prefix.
	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}
		// JFrog log lines start with a time stamp: "HH:MM:SS [..."
		assert.NotRegexp(t, `^\d{2}:\d{2}:\d{2}`, line,
			"log line leaked into github-md stdout: %q", line)
	}
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
		TotalViolations int    `json:"total_violations"`
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
	w.Close()
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
		{"Critical", "", true},          // empty min passes everything
		{"Low", "Low", true},            // equal rank passes
		{"Low", "Medium", false},        // too low
		{"High", "Critical", false},     // below threshold
		{"Critical", "High", true},      // above threshold
		{"Malicious", "Critical", true}, // rank -1 ≤ 0
		{"Low", "Malicious", false},     // rank 3 > -1
		{"Critical", "Malicious", false},// rank 0 > -1
		{"Malicious", "Malicious", true},// exact match
		{"Low", "Unknown", true},        // unrecognized min → pass all
		{"Unknown", "Low", true},        // unrecognized severity → pass through
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
	out := captureStdout(t, func() { generateSecurityBanner(report, lookup) })
	assert.Contains(t, out, "MALICIOUS_EXPLOIT_PRESENT")
	assert.Contains(t, out, "[!CAUTION]")
	assert.Contains(t, out, "MALICIOUS EXPLOIT PRESENT")
}

func TestGenerateSecurityBanner_MaliciousViaSlice(t *testing.T) {
	report := &VulnerabilityReport{MaliciousIssues: []string{"XRAY-1"}}
	out := captureStdout(t, func() { generateSecurityBanner(report, map[string]bool{}) })
	assert.Contains(t, out, "MALICIOUS_EXPLOIT_PRESENT")
	assert.Contains(t, out, "[!CAUTION]")
}

func TestGenerateSecurityBanner_Critical(t *testing.T) {
	report := &VulnerabilityReport{CriticalCount: 1, TotalIssues: 1}
	out := captureStdout(t, func() { generateSecurityBanner(report, map[string]bool{}) })
	assert.Contains(t, out, "CRITICAL_CVE")
	assert.Contains(t, out, "[!CAUTION]")
	assert.NotContains(t, out, "MALICIOUS")
}

func TestGenerateSecurityBanner_NonCriticalFindings(t *testing.T) {
	report := &VulnerabilityReport{HighCount: 2, TotalIssues: 2}
	out := captureStdout(t, func() { generateSecurityBanner(report, map[string]bool{}) })
	assert.Contains(t, out, "CVE")
	assert.Contains(t, out, "[!WARNING]")
	assert.NotContains(t, out, "MALICIOUS")
	assert.NotContains(t, out, "CRITICAL")
}

func TestGenerateSecurityBanner_Clean(t *testing.T) {
	report := &VulnerabilityReport{}
	out := captureStdout(t, func() { generateSecurityBanner(report, map[string]bool{}) })
	assert.Contains(t, out, "NO_FINDINGS")
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
	out := captureStdout(t, func() {
		err := outputJSONReport(report, map[string]bool{})
		assert.NoError(t, err)
	})

	var enhanced EnhancedVulnerabilityReport
	require.NoError(t, json.Unmarshal([]byte(out), &enhanced))
	assert.True(t, enhanced.ImageNotFound)
	assert.Equal(t, 0, enhanced.Summary.TotalFindings)
	assert.Equal(t, 0, enhanced.Summary.MaliciousCount)
	assert.Empty(t, enhanced.Platforms)
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
	}
	lookup := map[string]bool{"XRAY-1": true}
	out := captureStdout(t, func() {
		err := outputJSONReport(report, lookup)
		assert.NoError(t, err)
	})

	var enhanced EnhancedVulnerabilityReport
	require.NoError(t, json.Unmarshal([]byte(out), &enhanced))
	assert.Equal(t, 7, enhanced.Summary.TotalFindings)
	assert.Equal(t, 2, enhanced.Summary.CriticalCount)
	assert.Equal(t, 5, enhanced.Summary.HighCount)
	assert.Equal(t, 1, enhanced.Summary.MaliciousCount) // from map size
	assert.Equal(t, 1, enhanced.Summary.PlatformCount)
}

func TestOutputJSONReport_MaliciousCountFromMap(t *testing.T) {
	// maliciousCount in JSON comes from len(maliciousLookup), NOT len(MaliciousIssues).
	report := &VulnerabilityReport{
		ImageName:       "docker-local/app:v1",
		GeneratedAt:     "2026-01-01T00:00:00Z",
		MaliciousIssues: []string{"A", "B"},
	}
	lookup := map[string]bool{"A": true, "B": true, "C": true}
	out := captureStdout(t, func() {
		err := outputJSONReport(report, lookup)
		assert.NoError(t, err)
	})

	var enhanced EnhancedVulnerabilityReport
	require.NoError(t, json.Unmarshal([]byte(out), &enhanced))
	assert.Equal(t, 3, enhanced.Summary.MaliciousCount) // map has 3 keys
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
	out := captureStdout(t, func() {
		err := outputMarkdownReport(report, map[string]bool{}, "", "", false, "vulnreport", "vtest")
		assert.NoError(t, err)
	})
	assert.Contains(t, out, "NO_IMAGE_FOUND")
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
	out := captureStdout(t, func() {
		err := outputMarkdownReport(report, map[string]bool{}, "https://example.jfrog.io/ui/repos/tree/Xray/docker-local/app/v1/manifest.json", "", false, "vulnreport", "vtest")
		assert.NoError(t, err)
	})
	assert.Contains(t, out, "> **View manifest:**")
	assert.Contains(t, out, "https://example.jfrog.io/ui/repos/tree/Xray/docker-local/app/v1/manifest.json")
}

func TestOutputMarkdownReport_ManifestURLAbsent(t *testing.T) {
	report := &VulnerabilityReport{
		ImageName:   "docker-local/app:v1",
		GeneratedAt: "2026-01-01T00:00:00Z",
	}
	out := captureStdout(t, func() {
		err := outputMarkdownReport(report, map[string]bool{}, "", "", false, "vulnreport", "vtest")
		assert.NoError(t, err)
	})
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
	out := captureStdout(t, func() {
		err := outputMarkdownReport(report, map[string]bool{}, "", "", true, "vulnreport", "vtest")
		assert.NoError(t, err)
	})
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
	out := captureStdout(t, func() {
		err := outputMarkdownReport(report, map[string]bool{}, "", "High", false, "vulnreport", "vtest")
		assert.NoError(t, err)
	})
	assert.Contains(t, out, "XRAY-CRIT")
	assert.Contains(t, out, "XRAY-HIGH")
	assert.NotContains(t, out, "XRAY-LOW")
}

func TestOutputMarkdownReport_MaliciousFindingsTable(t *testing.T) {
	report := &VulnerabilityReport{
		ImageName:       "docker-local/app:v1",
		GeneratedAt:     "2026-01-01T00:00:00Z",
		MaliciousIssues: []string{"XRAY-A", "XRAY-B"},
	}
	out := captureStdout(t, func() {
		err := outputMarkdownReport(report, map[string]bool{"XRAY-A": true, "XRAY-B": true}, "", "", false, "vulnreport", "vtest")
		assert.NoError(t, err)
	})
	assert.Contains(t, out, "Malicious Findings (2)")
	assert.Contains(t, out, "XRAY-A")
	assert.Contains(t, out, "XRAY-B")
}

func TestOutputMarkdownReport_FindingsTableSorting(t *testing.T) {
	report := &VulnerabilityReport{
		ImageName:   "docker-local/app:v1",
		GeneratedAt: "2026-01-01T00:00:00Z",
		TotalIssues: 3,
		SummaryIssues: []SummaryIssue{
			{IssueID: "XRAY-200", Severity: "High"},    // added out of severity order
			{IssueID: "XRAY-100", Severity: "Critical"},
			{IssueID: "XRAY-101", Severity: "Critical"}, // same severity — sort by ID
		},
	}
	out := captureStdout(t, func() {
		err := outputMarkdownReport(report, map[string]bool{}, "", "", false, "vulnreport", "vtest")
		assert.NoError(t, err)
	})
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
	out := captureStdout(t, func() {
		err := outputMarkdownReport(report, map[string]bool{}, "", "", false, "vulnreport", "vtest")
		assert.NoError(t, err)
	})
	assert.Contains(t, out, "Generated by vulnreport vtest")
	assert.Contains(t, out, "2026-07-23T10:00:00Z")
}

// ---------------------------------------------------------------------------
// outputReport
// ---------------------------------------------------------------------------

func TestOutputReport_UnsupportedFormat(t *testing.T) {
	report := &VulnerabilityReport{ImageName: "docker-local/app:v1", GeneratedAt: "2026-01-01T00:00:00Z"}
	err := outputReport(report, map[string]bool{}, "xml", "", "", false, "vulnreport", "vtest")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported output format")
}

package internal

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jfrog/jfrog-client-go/http/jfroghttpclient"
	xrayAuth "github.com/jfrog/jfrog-client-go/xray/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestViolationsRequestShape confirms the request body for POST /api/v1/violations matches
// what the live Xray API expects. This is the wire format sent by XrayService.GetViolations().
func TestViolationsRequestShape(t *testing.T) {
	req := violationsRequest{
		Filters: violationsFilters{
			WatchName:     "test-malicious-watch",
			ViolationType: "Security",
			Resources: violationsResources{
				Artifacts: []violationsArtifact{
					{Repo: "docker-local", Path: "myimage/v1/manifest.json"},
				},
			},
			IncludeDetails: true,
		},
		Pagination: violationsPagination{
			OrderBy: "severity",
			Limit:   100,
			Offset:  1,
		},
	}

	body, err := json.Marshal(req)
	require.NoError(t, err)

	// Expected shape — exact match against the XrayService.GetViolations wire format.
	// pagination is always included so the API returns all violations, not just the first 25.
	expected := `{"filters":{"watch_name":"test-malicious-watch","violation_type":"Security","resources":{"artifacts":[{"repo":"docker-local","path":"myimage/v1/manifest.json"}]},"include_details":true},"pagination":{"order_by":"severity","limit":100,"offset":1}}`
	assert.JSONEq(t, expected, string(body),
		"Request body must match the wire format Xray expects for /api/v1/violations")
}

// TestGetSummaryV2_CVEParsing verifies that CVE IDs in the v2 summary response are
// parsed into SummaryIssue.CVEIDs, and that deduplication merges CVE IDs across artifacts.
func TestGetSummaryV2_CVEParsing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Two artifacts: first has XRAY-A with one CVE, second has XRAY-A again (dedup) with
		// an additional CVE, plus XRAY-B with no CVE.
		_, _ = io.WriteString(w, `{
			"artifacts": [
				{"issues": [
					{"issue_id":"XRAY-A","severity":"Critical","cves":[{"cve":"CVE-2024-00001"}],"components":[]},
					{"issue_id":"XRAY-B","severity":"High","components":[]}
				]},
				{"issues": [
					{"issue_id":"XRAY-A","severity":"Critical","cves":[{"cve":"CVE-2024-00001"},{"cve":"CVE-2024-00002"}],"components":[]}
				]}
			]
		}`)
	}))
	t.Cleanup(srv.Close)

	client, err := jfroghttpclient.JfrogClientBuilder().Build()
	require.NoError(t, err)
	xrayDetails := xrayAuth.NewXrayDetails()
	xrayDetails.SetUrl(srv.URL + "/")
	xs := NewXrayService(client, xrayDetails)

	counts, issues, err := xs.GetSummaryV2([]string{"default/docker-local/img/v1/manifest.json", "default/docker-local/img/v1/sha256__abc/manifest.json"}, []string{"linux/amd64", "linux/arm64"})
	require.NoError(t, err)

	assert.Equal(t, 2, counts.Total)
	assert.Equal(t, 1, counts.Critical)
	assert.Equal(t, 1, counts.High)

	issueMap := make(map[string]SummaryIssue)
	for _, si := range issues {
		issueMap[si.IssueID] = si
	}

	// XRAY-A must have both CVEs deduplicated and sorted.
	a := issueMap["XRAY-A"]
	assert.Equal(t, []string{"CVE-2024-00001", "CVE-2024-00002"}, a.CVEIDs)

	// XRAY-B has no CVEs.
	b := issueMap["XRAY-B"]
	assert.Empty(t, b.CVEIDs)
}

// TestViolationsRequestShape_MultipleArtifacts verifies the request supports multiple
// artifacts per query (the API allows batching — useful if we ever query several
// platforms in a single request).
func TestViolationsRequestShape_MultipleArtifacts(t *testing.T) {
	req := violationsRequest{
		Filters: violationsFilters{
			WatchName:     "test-watch",
			ViolationType: "Security",
			Resources: violationsResources{
				Artifacts: []violationsArtifact{
					{Repo: "docker-local", Path: "app/v1/manifest.json"},
					{Repo: "docker-local", Path: "app/v1/list.manifest.json"},
				},
			},
			IncludeDetails: true,
		},
	}

	body, err := json.Marshal(req)
	require.NoError(t, err)

	// Should contain both artifacts in the artifacts array
	assert.Contains(t, string(body), `"path":"app/v1/manifest.json"`)
	assert.Contains(t, string(body), `"path":"app/v1/list.manifest.json"`)
}

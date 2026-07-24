package internal

import (
	"encoding/json"
	"testing"

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

package internal

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestViolationsRequestShape confirms the request body for POST /api/v1/violations matches
// what the live Xray API expects. This is the wire format we'll send from the new
// xray_sdk.go XrayService.GetViolations() method (Phase 3).
//
// The expected JSON shape must match the current xray_cli.go queryXrayViolationsViaCLI
// request body (xray_cli.go:310-321) so we maintain parity during the migration.
func TestViolationsRequestShape(t *testing.T) {
	req := violationsRequest{
		Filters: violationsFilters{
			WatchName:      "dockerlocal-malicious-critical",
			ViolationType:  "Security",
			Resources: violationsResources{
				Artifacts: []violationsArtifact{
					{Repo: "docker-local", Path: "jmhxraytest/15/manifest.json"},
				},
			},
			IncludeDetails: true,
		},
	}

	body, err := json.Marshal(req)
	require.NoError(t, err)

	// Expected shape — exact match against the current xray_cli.go:310-321 wire format
	expected := `{"filters":{"watch_name":"dockerlocal-malicious-critical","violation_type":"Security","resources":{"artifacts":[{"repo":"docker-local","path":"jmhxraytest/15/manifest.json"}]},"include_details":true}}`
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

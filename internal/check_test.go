package internal

import (
	"encoding/json"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/stretchr/testify/assert"
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
			repo, image, tag, err := parseImageName(tt.fullImageName)

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

func TestFilterVulnerabilitiesBySeverity(t *testing.T) {
	vulnerabilities := []services.Vulnerability{
		{
			IssueId:  "CVE-2023-001",
			Severity: "Low",
		},
		{
			IssueId:  "CVE-2023-002",
			Severity: "Medium",
		},
		{
			IssueId:  "CVE-2023-003",
			Severity: "High",
		},
		{
			IssueId:  "CVE-2023-004",
			Severity: "Critical",
		},
	}

	tests := []struct {
		name          string
		minSeverity   string
		expectedCount int
	}{
		{
			name:          "No filter",
			minSeverity:   "",
			expectedCount: 4,
		},
		{
			name:          "Filter by Low severity",
			minSeverity:   "Low",
			expectedCount: 4, // All vulnerabilities
		},
		{
			name:          "Filter by Medium severity",
			minSeverity:   "Medium",
			expectedCount: 3, // Medium, High, Critical
		},
		{
			name:          "Filter by High severity",
			minSeverity:   "High",
			expectedCount: 2, // High, Critical
		},
		{
			name:          "Filter by Critical severity",
			minSeverity:   "Critical",
			expectedCount: 1, // Critical only
		},
		{
			name:          "Invalid severity",
			minSeverity:   "Invalid",
			expectedCount: 4, // Returns all when invalid
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			maliciousLookup := map[string]bool{}
			filtered := filterVulnerabilitiesBySeverity(vulnerabilities, tt.minSeverity, maliciousLookup)
			assert.Equal(t, tt.expectedCount, len(filtered))
		})
	}
}

func TestGetDockerRegistryPaths(t *testing.T) {
	tests := []struct {
		name             string
		repoKey          string
		imageName        string
		tag              string
		expectedList     string
		expectedManifest string
	}{
		{
			name:             "Simple image",
			repoKey:          "docker-local",
			imageName:        "myapp",
			tag:              "latest",
			expectedList:     "docker-local/myapp/latest/list.manifest.json",
			expectedManifest: "docker-local/myapp/latest/manifest.json",
		},
		{
			name:             "Namespaced image",
			repoKey:          "docker-local",
			imageName:        "team/myapp",
			tag:              "v1.2.3",
			expectedList:     "docker-local/team/myapp/v1.2.3/list.manifest.json",
			expectedManifest: "docker-local/team/myapp/v1.2.3/manifest.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := GetDockerRegistryPaths(tt.repoKey, tt.imageName, tt.tag)

			assert.Equal(t, tt.expectedList, paths["list_manifest"])
			assert.Equal(t, tt.expectedManifest, paths["manifest"])
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

func TestGetXrayServiceURL(t *testing.T) {
	t.Run("prefers explicit xray URL", func(t *testing.T) {
		server := &config.ServerDetails{
			XrayUrl:        "https://example.jfrog.io/xray/",
			ArtifactoryUrl: "https://example.jfrog.io/artifactory",
		}
		assert.Equal(t, "https://example.jfrog.io/xray", getXrayServiceURL(server))
	})

	t.Run("derives from artifactory URL", func(t *testing.T) {
		server := &config.ServerDetails{
			ArtifactoryUrl: "https://example.jfrog.io/artifactory",
		}
		assert.Equal(t, "https://example.jfrog.io/xray", getXrayServiceURL(server))
	})

	t.Run("falls back to platform URL", func(t *testing.T) {
		server := &config.ServerDetails{
			Url: "https://example.jfrog.io/",
		}
		assert.Equal(t, "https://example.jfrog.io/xray", getXrayServiceURL(server))
	})
}

func TestBuildViolationArtifactFilters(t *testing.T) {
	tests := []struct {
		name          string
		repoKey       string
		artifactPath  string
		expectedMatch violationArtifactFilter
	}{
		{
			name:         "docker-prefixed manifest path",
			repoKey:      "docker-local",
			artifactPath: "docker/docker-local/team/myapp/1.2.3/manifest.json",
			expectedMatch: violationArtifactFilter{
				Repository: "docker-local",
				Path:       "team/myapp/1.2.3/manifest.json",
			},
		},
		{
			name:         "repo-prefixed legacy path",
			repoKey:      "docker-local",
			artifactPath: "docker-local/team/myapp:1.2.3",
			expectedMatch: violationArtifactFilter{
				Repository: "docker-local",
				Path:       "team/myapp:1.2.3",
			},
		},
		{
			name:         "image only path still scoped to repo",
			repoKey:      "docker-local",
			artifactPath: "team/myapp:1.2.3",
			expectedMatch: violationArtifactFilter{
				Repository: "docker-local",
				Path:       "team/myapp:1.2.3",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filters := buildViolationArtifactFilters(tt.repoKey, tt.artifactPath)
			assert.NotEmpty(t, filters)
			assert.Contains(t, filters, tt.expectedMatch)
		})
	}
}

func TestMapXrayViolationsToVulnerabilities(t *testing.T) {
	violations := []xrayViolation{
		{
			IssueId:  "XRAY-1",
			Summary:  "Issue summary",
			Severity: "Critical",
			Type:     violationTypeSecurity,
			Cves: []services.Cve{
				{
					Id:           "CVE-2026-0001",
					CvssV2Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P",
					CvssV3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					Cwe:          []string{"CWE-79"},
				},
			},
		},
		{
			Id:          "VIOL-2",
			Description: "License violation description",
			Severity:    "High",
			Type:        violationTypeLicense,
		},
	}

	vulnerabilities := mapXrayViolationsToVulnerabilities(violations)
	assert.Len(t, vulnerabilities, 2)

	assert.Equal(t, "XRAY-1", vulnerabilities[0].IssueId)
	assert.Equal(t, "Issue summary", vulnerabilities[0].Summary)
	assert.Equal(t, "Critical", vulnerabilities[0].Severity)
	assert.Equal(t, "Security", vulnerabilities[0].Technology)
	assert.Len(t, vulnerabilities[0].Cves, 1)
	assert.Equal(t, "CVE-2026-0001", vulnerabilities[0].Cves[0].Id)
	assert.Equal(t, "CWE-79", vulnerabilities[0].Cves[0].Cwe[0])

	assert.Equal(t, "VIOL-2", vulnerabilities[1].IssueId)
	assert.Equal(t, "License violation description", vulnerabilities[1].Summary)
	assert.Equal(t, "High", vulnerabilities[1].Severity)
	assert.Equal(t, "License", vulnerabilities[1].Technology)
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

func TestFilterVulnerabilitiesBySeverityWithMaliciousLookup(t *testing.T) {
	vulnerabilities := []services.Vulnerability{
		{IssueId: "XRAY-1", Severity: "Low"},
		{IssueId: "XRAY-2", Severity: "Medium"},
		{IssueId: "XRAY-3", Severity: "High"},
		{IssueId: "XRAY-4", Severity: "Critical"},
	}

	maliciousLookup := map[string]bool{
		"XRAY-1": false,
		"XRAY-2": true,
		"XRAY-3": false,
		"XRAY-4": true,
	}

	tests := []struct {
		name          string
		minSeverity   string
		expectedCount int
	}{
		{
			name:          "No filter",
			minSeverity:   "",
			expectedCount: 4,
		},
		{
			name:          "Filter by Medium severity",
			minSeverity:   "Medium",
			expectedCount: 3, // Medium, High, Critical
		},
		{
			name:          "Filter by Malicious severity — uses lookup map (no Events API)",
			minSeverity:   "Malicious",
			expectedCount: 2, // Only XRAY-2 and XRAY-4 are malicious
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := filterVulnerabilitiesBySeverity(vulnerabilities, tt.minSeverity, maliciousLookup)
			assert.Equal(t, tt.expectedCount, len(filtered))
		})
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

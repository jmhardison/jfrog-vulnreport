package internal

import (
	"encoding/json"
	"fmt"
	"strings"
)



func GetDockerRegistryPaths(repoKey, imageName, tag string) map[string]string {
	base := fmt.Sprintf("%s/%s/%s", repoKey, imageName, tag)
	return map[string]string{
		"list_manifest": base + "/list.manifest.json",
		"manifest":      base + "/manifest.json",
	}
}

func GetDigestPaths(repoKey, digest string) []string {
	normalizedDigest := strings.TrimPrefix(digest, "sha256:")
	return []string{
		fmt.Sprintf("%s/blobs/sha256/%s", repoKey, normalizedDigest),
		fmt.Sprintf("%s/blobs/sha256__%s", repoKey, normalizedDigest),
		fmt.Sprintf("%s/%s", repoKey, normalizedDigest),
		fmt.Sprintf("%s/manifests/%s", repoKey, normalizedDigest),
	}
}

// extractRepoFromPath extracts the repository key from an artifact path.
// Example: "docker-local/jmhxraytest/10/manifest.json" → "docker-local"
func extractRepoFromPath(path string) string {
	if idx := strings.IndexByte(path, '/'); idx >= 0 {
		return path[:idx]
	}
	return ""
}

func IsValidManifestContent(content []byte) bool {
	if len(content) == 0 {
		return false
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(content, &payload); err != nil {
		return false
	}

	schemaVersionRaw, exists := payload["schemaVersion"]
	if !exists {
		return false
	}

	var schemaVersion int
	if err := json.Unmarshal(schemaVersionRaw, &schemaVersion); err != nil {
		return false
	}

	return schemaVersion > 0
}

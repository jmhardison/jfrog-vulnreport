package internal

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jfrog/jfrog-client-go/utils/log"
)

// dockerPath represents a discovered artifact path and its associated metadata.
type dockerPath struct {
	path    string   // Xray artifact path to query for vulnerabilities
	digests []string // sha256 digests (empty if not from manifest list)
	isList  bool     // true if this is a manifest list (multi-platform image)
	os      string   // platform OS (e.g. "linux", "windows") — parsed from manifest body
	arch    string   // platform architecture (e.g. "amd64", "arm64") — parsed from manifest body
}

// rtArtifact represents an artifact from Artifactory search results.
type rtArtifact struct {
	Path   string            `json:"path"`
	SHA256 string            `json:"sha256"`
	Props  map[string][]string `json:"props"`
}

// discoverImageArtifacts handles dual-path discovery for both multi-platform and single-platform images.
// Uses Artifactory AQL search to find manifests, then expands list.manifest.json into per-platform entries.
func discoverImageArtifacts(artSvc *ArtifactoryService, repoKey, imageName, tag string) ([]dockerPath, error) {
	// Step 1: Search Artifactory for Docker image files (manifests and blobs)
	searchPattern := fmt.Sprintf("%s/%s/%s/*", repoKey, imageName, tag)
	log.Info(fmt.Sprintf("Searching Artifactory for Docker artifacts: %s", searchPattern))

	artifacts, err := artSvc.SearchArtifacts(searchPattern)
	if err != nil {
		return nil, fmt.Errorf("artifactory search failed: %w", err)
	}

	if len(artifacts) == 0 {
		log.Debug("No artifacts found in Artifactory for this image")
		return nil, nil
	}

	// Collect all manifest entries (single-platform manifests + list.manifest.json)
	var singlePlatformPaths []dockerPath
	var listManifestArt *rtArtifact // The list.manifest.json artifact (if found)

	for _, art := range artifacts {
		path := art.Path
		isListManifest := strings.HasSuffix(path, "/list.manifest.json")
		isManifest := strings.HasSuffix(path, "/manifest.json") && !isListManifest

		if isListManifest || isManifest {
			log.Info(fmt.Sprintf("Found %s in Artifactory", path))

			// Extract sha256 from path or properties
			digest := extractSHA256FromPathOrProps(art)
			if digest == "" {
				log.Debug(fmt.Sprintf("No sha256 found for %s, skipping", path))
				continue
			}

			osStr, archStr := parseOSArchFromProps(art.Props)

			if isListManifest {
				listManifestArt = &art // Remember the list manifest for later expansion
				log.Info(fmt.Sprintf("Multi-platform image detected via list.manifest.json"))
			} else {
				singlePlatformPaths = append(singlePlatformPaths, dockerPath{
					path:    path,
					digests: []string{digest},
					isList:  false,
					os:      osStr,
					arch:    archStr,
				})
			}
		}
	}

	// If we found a list.manifest.json, expand it into per-platform entries.
	// The list manifest lives in Artifactory storage (not Xray), so we fetch its body directly from Artifactory
	// using the SDK's authenticated HTTP client — Xray's artifact-get endpoint doesn't serve raw file content.
	//
	// When a list manifest is present, discard singlePlatformPaths: AQL returns both list.manifest.json
	// and the individual sha256__<digest>/manifest.json entries, and expandListManifest generates those
	// same sha256__ paths from the list body. Returning both would cause each platform to be queried twice.
	if listManifestArt != nil {
		listPaths, err := expandListManifest(artSvc, listManifestArt, repoKey, imageName, tag)
		if err != nil {
			return nil, fmt.Errorf("failed to expand list.manifest.json: %w", err)
		}
		return listPaths, nil
	}

	// Single-platform image (or no list manifest found)
	if len(singlePlatformPaths) > 0 {
		log.Info(fmt.Sprintf("Single-platform image detected via manifest.json"))
	} else {
		log.Debug("No manifest files found in Artifactory search results")
	}

	return singlePlatformPaths, nil
}

// expandListManifest fetches a list.manifest.json body and expands it into per-platform dockerPath entries.
// The list manifest is stored in Artifactory (not Xray), so we fetch its raw content from Artifactory storage
// using the artifact's full path. Platform digests extracted here are then used as Xray query paths below.
func expandListManifest(artSvc *ArtifactoryService, listArt *rtArtifact, repoKey, imageName, tag string) ([]dockerPath, error) {
	// Extract the relative artifact path (everything after the repo key) from the full Artifactory path.
	// e.g., "docker-local/web-server/latest/list.manifest.json" → "web-server/latest/list.manifest.json"
	relPath := listArt.Path
	if idx := strings.Index(listArt.Path, "/"); idx >= 0 {
		relPath = listArt.Path[idx+1:]
	}

	// Fetch the list manifest body from Artifactory storage (not Xray — Xray's artifact-get doesn't serve raw file content).
	body, err := artSvc.FetchArtifactBody(repoKey, relPath)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch list.manifest.json body from Artifactory: %w", err)
	}

	var listManifest ManifestList
	if err := json.Unmarshal(body, &listManifest); err != nil {
		return nil, fmt.Errorf("failed to parse list.manifest.json: %w", err)
	}

	if len(listManifest.Manifests) == 0 {
		log.Debug("No platform manifests in list.manifest.json")
		return nil, nil
	}

	log.Info(fmt.Sprintf("Expanding list.manifest.json into %d platform entries", len(listManifest.Manifests)))

	var paths []dockerPath
	for _, entry := range listManifest.Manifests {
		if entry.Digest == "" || !strings.HasPrefix(entry.Digest, "sha256:") {
			continue
		}

		// Skip entries with unknown OS or architecture — these are typically SBOM-type images or malformed manifests.
		// Real container platforms always have both os and architecture set (e.g., linux/amd64, windows/arm64).
		if strings.EqualFold(entry.Platform.OS, "unknown") || entry.Platform.OS == "" {
			log.Debug(fmt.Sprintf("Skipping platform entry with unknown OS: digest=%s", entry.Digest))
			continue
		}
		if strings.EqualFold(entry.Platform.Architecture, "unknown") || entry.Platform.Architecture == "" {
			log.Debug(fmt.Sprintf("Skipping platform entry with unknown architecture: digest=%s", entry.Digest))
			continue
		}

		digest := strings.TrimPrefix(entry.Digest, "sha256:")
		// Artifactory stores per-platform manifests under sha256__<digest>/manifest.json,
		// not the Docker registry API format manifests/<digest>.
		path := fmt.Sprintf("%s/%s/%s/sha256__%s/manifest.json", repoKey, imageName, tag, digest)

		paths = append(paths, dockerPath{
			path:    path,
			digests: []string{"sha256:" + digest},
			isList:  true,
			os:      entry.Platform.OS,
			arch:    entry.Platform.Architecture,
		})

		log.Debug(fmt.Sprintf("Platform entry: %s/%s (digest: sha256:%s)", entry.Platform.OS, entry.Platform.Architecture, digest))
	}

	return paths, nil
}

// extractSHA256FromPathOrProps extracts sha256 from the artifact path or its properties.
func extractSHA256FromPathOrProps(art rtArtifact) string {
	// Try sha256 property first (most reliable)
	if art.SHA256 != "" {
		return art.SHA256
	}

	// Try docker.manifest.digest property
	if vals, ok := art.Props["docker.manifest.digest"]; ok && len(vals) > 0 {
		digest := vals[0]
		return strings.TrimPrefix(digest, "sha256:")
	}

	// Extract from path (e.g., docker-local/jmhxraytest/10/sha256__<digest>/manifest.json)
	parts := strings.Split(art.Path, "/")
	for i, part := range parts {
		if strings.HasPrefix(part, "sha256__") && i > 0 {
			return strings.TrimPrefix(part, "sha256__")
		}
	}

	return ""
}

// parseOSArchFromProps extracts OS and architecture from Docker image properties.
func parseOSArchFromProps(props map[string][]string) (osStr, arch string) {
	if vals, ok := props["docker.os"]; ok && len(vals) > 0 {
		osStr = vals[0]
	}
	if vals, ok := props["docker.architecture"]; ok && len(vals) > 0 {
		arch = vals[0]
	}
	return osStr, arch
}

// FilterManifestsByPlatform filters a slice of dockerPaths by OS and/or architecture.
func FilterManifestsByPlatform(paths []dockerPath, arch, os string) []dockerPath {
	var filtered []dockerPath
	for _, p := range paths {
		if arch != "" && p.arch != "" && !strings.EqualFold(p.arch, arch) {
			continue
		}
		if os != "" && p.os != "" && !strings.EqualFold(p.os, os) {
			continue
		}
		filtered = append(filtered, p)
	}
	return filtered
}

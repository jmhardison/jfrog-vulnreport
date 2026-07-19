# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

JFrog CLI plugin that reads existing Xray scan results for a Docker image and outputs a consolidated vulnerability report. The plugin registers as a JFrog CLI subcommand (`jf jfrog-vulnreport check`).

## Build & Run

```bash
# Build the binary
go build -o jfrog-vulnreport .

# Install as JFrog CLI plugin
jf plugin install jfrog-vulnreport

# Uninstall
jf plugin uninstall jfrog-vulnreport

# Run tests
go test ./...
go test ./commands/...
go test ./internal/...
```

## Architecture

### Entry point (`main.go`)

Registers the app with `plugins.PluginMain`, wiring up a single subcommand: `check`. The version is hardcoded in `getApp()`.

### Command layer (`commands/check.go`)

Defines the CLI surface — arguments, flags (server-id, platform, os, fail-on-vuln, output, min-severity, show-findings, debug-paths, docker-registry-url), and delegates to `internal.RunCheckCommand`.

### Internal package (`internal/`)

- **`check_runner.go`** — Core orchestration: parses image name → configures JFrog connections (Artifactory + Xray) → queries Docker registry for manifests → calls Xray SummaryService for vulnerabilities → formats and outputs report. Contains helper functions for malicious package detection via Events API, severity filtering, issue type extraction, and both JSON/markdown output formatting.
- **`models.go`** — Data structures: `DockerManifest`, `ManifestList`, `PlatformManifest`, `CheckConfiguration`, `VulnerabilityReport`, `EnhancedVulnerabilityReport`, `CompactFinding`. Also defines the `DockerRegistryClient` for manifest retrieval.
- **`helpers.go`** — Pure utilities: platform-based manifest filtering, Docker registry path construction, digest path generation, manifest content validation.

### Key patterns

- Vulnerabilities are queried from Xray's SummaryService; if direct paths fail, a discovery approach tries multiple Docker image path formats before giving up.
- Malicious package detection uses the JFrog Events API (`/api/v2/events/{issueId}`) with an in-memory cache (`maliciousCache`) keyed by issue ID.
- Output supports two formats: `json` (default, produces `EnhancedVulnerabilityReport`) and `github-md` (silent markdown with security banner).

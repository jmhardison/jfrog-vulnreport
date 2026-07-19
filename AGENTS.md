# AGENTS.md

## Project Overview

JFrog CLI plugin that reads existing Xray scan results for a Docker image and outputs a consolidated vulnerability report. Registers as `jf jfrog-vulnreport check`.

**NOT a standalone scanner** — it queries artifacts already indexed in JFrog/Xray and enriches them with security findings from cached scans. Users should use the native JFrog CLI Xray command (or IDE integrations) for scanning, then this plugin for post-scan reporting.

## Build & Run

### Local Development Cycle (REQUIRED)

All code changes must compile, pass tests, and be installed before claiming they work. Follow this cycle:

```bash
go build ./...                                    # 1. Verify compilation
go test ./...                                     # 2. Run all tests
go build -o jfrog-vulnreport . && cp jfrog-vulnreport ~/.jfrog/plugins/jfrog-vulnreport/bin/  # 3. Install binary for JFrog CLI testing
```

**The built binary must be copied to `~/.jfrog/plugins/jfrog-vulnreport/bin/` before testing with the JFrog CLI.** Without this step, `jf jfrog-vulnreport check ...` will not pick up your changes.

### Production Install (for persistent use)

```bash
go build -o jfrog-vulnreport . && jf plugin install jfrog-vulnreport  # Install as JFrog CLI plugin
```

## Architecture Notes

- **Single command**: `check` — no subcommands planned
- **Output formats**: `json` (default, enhanced report with image metadata/counts), `github-md` (silent markdown for GitHub CI)
- Image tag input → digest mapping resolved via Xray API; digests map to cached scan artifacts by `(scanType, sha256)`

### Code Organization & File Responsibilities

**Entry point**: `main.go` — registers plugin with `github.com/jfrog/jfrog-cli-core/v2/plugins`, declares build time (`internal.BuildTime`) and version (`internal.Version`).

**CLI command**: `commands/check.go:22-30` — single file, contains all CLI flags (+argument), argument/flag/env registration functions. Delegates to the internal runner via `helperinternal.RunCheckCommand(c)`. Any new command must register in main.go with both CLI args and env vars (currently unregistered).

**Internal logic**: `/internal/` package contains business logic split across four files:
- `check_runner.go` — main command implementation, orchestrates Xray calls and report generation. Contains `RunCheckCommand`, `generateVulnerabilityReport`, output formatters (`outputJSONReport`, `outputMarkdownReport`), severity filtering, and malicious detection via Violations API lookup map.
- `models.go` — Go types matching Xray JSON payloads (`DockerManifest`, `VulnerabilityReport`, `EnhancedVulnerabilityReport`, `CompactFinding`). Also defines the `DockerRegistryClient` for manifest retrieval.
- `helpers.go` — pure utilities: platform-based manifest filtering, Docker registry path construction, digest path generation, manifest content validation.
- `docker_paths.go` — Docker image path discovery using list.manifest.json pattern with multi-platform support. Contains `discoverImageArtifacts`, `FilterManifestsByPlatform`.
- `xray_cli.go` — JFrog CLI subprocess wrappers for Xray API calls (bypasses JWT audience restrictions). Defines the `violationWithMalicious` struct and `queryXrayViolationsViaCLIVulnerabilitiesWithMalicious` function that extracts malicious_package status from the Violations response.

**Build / install**: go build + jfrog CLI installation flow; plugin registered with framework via `github.com/jfrog/jfrog-cli-core/v2/plugins`. Plugin name: `jfrog-vulnreport` (lowercase + numbers/dashes, max 30 chars).

## Testing & Publishing

- Add tests before publishing — GitHub Actions runs `go vet ./... && go test ./...` and checks for test coverage
- Tests live in the same `_test.go` files alongside their source packages (`internal/check_test.go`)

### Publishing to Registry

1. Add a YAML descriptor (e.g., `jfrog-vulnreport.yml`) to [jfrog-cli-plugins-reg](https://github.com/jfrog/jfrog-cli-plugins-reg/tree/master/plugins)
2. Include required fields: `pluginName`, `version` (with `v` prefix), `repository`
3. Accept the developer terms file from that registry before PR is merged

### Registry Build & Upload Flow (from /jfrog-vulnreport/)

```bash
cat <<EOF > jfrog-vulnreport.yml
name: jfrog-vulnreport
summary: Reports vulnerabilities, licenses, components, traceability from Xray scans on Docker images for compliance and supply chain security.
description: |
  The JFrog CLI vuln-report plugin is a single-command plugin that can query existing vulnerability scan results for an image...
version: v0.1.2
maintainers:
- name: Jonathan Hardison
  type: individual
  username: jmhardison
repository: git+https://github.com/jmhardison/jfrog-vulnreport.git@main
EOF

cd /jfrog-vulnreport && go build -o jfrog-vulnreport . && jf plugin create --file=jfrog-vulnreport.yml
```

## Architecture: Xray Query Pipeline (IMPORTANT)

### Three-Layer System

| Layer | System | Purpose | API to Use |
|-------|--------|---------|------------|
| 1 | **Artifactory** | Stores Docker manifests/blobs | `jf rt search` (REST API) |
| 2 | **Xray Violations** | Returns violation details with CVEs, severity, remediation, AND malicious_package status | `jf xr curl /api/v1/violations` |

### Workflow

```
1. Search Artifactory for manifest files:
   jf rt search "<repo>/<image>/<tag>/*"
   → Extract sha256 digest from path or docker.manifest.digest property

2. Query Xray Violations API with artifact path (NOT SummaryService):
   POST /api/v1/violations?projectKey=default
   Body: {"filters": {"resources": {"artifacts": [{"repo": "...", "path": "..."}]}, "include_details": true}}
   → Returns rich violation data including CVEs, severity, remediation, AND malicious_package per violation

3. Malicious package detection is extracted from the Violations response (step 2).
   No separate Events API calls are needed — the malicious_package field is included
   on each violation in the same response that provides vulnerability data.
```

**Critical**: The Xray SummaryService (`/api/v1/summary/artifact`) **hangs indefinitely** for Docker images. Always use the Violations API instead.

### Dual-Path Discovery (Single vs Multi-Platform Images)

Docker images come in two forms — **must handle both**:

| Type | What exists in Artifactory | How to discover |
|------|---------------------------|-----------------|
| **Single-platform** | `manifest.json` only | Search Artifactory → find manifest → extract sha256 from path/props |
| **Multi-platform** | `list.manifest.json` (with platform entries) | Search Artifactory → find list → parse component_ids for per-platform digests |

#### Discovery (Search Artifactory with Wildcard)

```
1. Search Artifactory:
   jf rt search "<repo>/<image>/<tag>/*"

2. Parse JSON results — each artifact has:
   - path: storage path (e.g., "docker-local/jmhxraytest/10/sha256__<digest>/manifest.json")
   - sha256: content hash
   - props.docker.manifest.digest: ["sha256:..."] (if present)

3. Find manifest files in results:
   - /list.manifest.json → multi-platform (Path A)
   - /manifest.json (not list) → single-platform (Path B)

4. Extract sha256 from path or properties, then query Xray Violations API with that path
```

#### Path A: Multi-Platform (list.manifest.json found)

```
1. Parse list.manifest.json body to get per-platform entries:
   GET /api/v1/artifact/get?path=<repo>/<image>/<tag>/list.manifest.json

2. Each entry has: digest, platform.os, platform.architecture

3. For each platform digest, query Xray Violations API:
   POST /api/v1/violations?projectKey=default
   Body: {"filters": {"resources": {"artifacts": [{"repo": "...", "path": "..."}]}}}
```

#### Path B: Single-Platform (manifest.json found)

```
1. Extract sha256 from path or properties

2. Query Xray Violations API with that path:
   POST /api/v1/violations?projectKey=default
   Body: {"filters": {"resources": {"artifacts": [{"repo": "...", "path": "..."}]}}}
```

### CLI Wrapper Approach (JWT Bypass)

All Xray API calls go through `jf xr curl` subprocess commands in `internal/xray_cli.go`. Direct SDK client calls fail with 401 due to JWT audience restrictions.

**Available wrappers:**
- `queryXrayViolationsViaCLIVulnerabilitiesWithMalicious(serverId, projectKey, artifactPath)` — Violations API (vulnerabilities + malicious_package) **← USE THIS FOR DOCKER IMAGES**
- `queryArtifactorySearchViaCLI(serverId, pattern)` — Artifactory search API (for manifest discovery)
- `fetchArtifactBodyViaCLI(serverId, artifactPath)` — GET raw artifact body

**DO NOT use:**
- Direct SDK Xray client calls (`xrManager.Client().SendPost`, etc.) — 401 JWT errors
- SummaryService (`/api/v1/summary/artifact`) — **hangs indefinitely for Docker images**

### Malicious Package Detection (Optimization)

The Violations API response already includes `malicious_package` on each violation. The code extracts this field during the initial Violations query and builds an in-memory lookup map (`map[string]bool` keyed by issue ID). All output functions use this pre-built map instead of making separate Events API calls per issue ID, eliminating N+1 HTTP requests.

**Key types:**
- `violationWithMalicious` (in `xray_cli.go`) — wraps `services.Vulnerability` with `MaliciousPackage bool`
- The lookup map is built in `generateVulnerabilityReport()` and passed to all output functions

### Project Key Flag

The `--project-key` flag (defaults to `"default"`) is required for Xray Violations API queries. This allows querying violations across multiple Xray projects in a multi-project JFrog Platform setup.

## File Structure Summary

```
.
├── /commands/        -> CLI command definitions (getCheckArguments, getCheckFlags)
│   └── check.go      -> Single file: CLI flags + arg parsing
├── /internal/        -> Business logic layer
│   ├── check_runner.go  -> Main command implementation, output formatting, severity filtering
│   ├── models.go        -> Types matching Xray JSON payloads (VulnerabilityReport, CompactFinding, etc.)
│   ├── helpers.go       -> Pure utilities: platform filtering, path construction, manifest validation
│   ├── docker_paths.go  -> Docker image path discovery with multi-platform support via list.manifest.json
│   └── xray_cli.go      -> CLI subprocess wrappers for Xray API calls + violationWithMalicious type
├── main.go                   -> Entry point: registers plugin with framework, declares build time and version
└── jfrog-vulnreport.yml     -> Plugin registry descriptor (name, summary, version, maintainers, repository)
```

### Gotchas / Lessons Learned

1. Some CLI flag methods (`GetServerId`, `GetRepo`) are deprecated — use the newer API when migrating
2. The Xray SummaryService (`/api/v1/summary/artifact`) hangs indefinitely for Docker images — always use the Violations API
3. Direct SDK Xray client calls fail with 401 due to JWT audience restrictions — all calls must go through `jf xr curl` subprocess wrappers
4. The Violations API returns `malicious_package` per violation — no separate Events API calls needed (extracted during initial query)
5. Docker image path discovery uses `list.manifest.json` pattern via Xray artifact search API — this is the only reliable way to find multi-platform images in JFrog/Xray

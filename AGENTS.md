# AGENTS.md

## Project Overview
JFrog CLI plugin that queries Xray's existing vulnerability scan results for Docker images across platforms. Registers as `jf jfrog-vulnreport check`.

**NOT a standalone scanner** — it reads artifacts already in JFrog/Xray and enriches them with security findings from cached scans. Users should use the native JFrog CLI Xray command (or IDE integrations) for scanning, then this plugin for post-scan reporting.

## Commands
```bash
go build -o jfrog-vulnreport .                    # Build binary
go test ./...                                       # Run tests
jf plugin install jfrog-vulnreport                # Install as JFrog CLI plugin (from source with no version tag)
cat /tmp/vulnerability_report.json | jq           # Inspect report output
diff -y <(jq -c . file1) <(jq -c . file2)        # Compare two report outputs
```

## Architecture Notes
- **Single command**: `check` — no subcommands planned
- **Output formats**: `json` (default, enhanced report structure with image metadata/counts), `github-md` (markdown, single line for GitHub)
- Image tag input → digest mapping resolved via Xray API (see "Go SDK Known Issues" below); digests map to cached scan artifacts by `(scanType, sha256)`

### Code Organization & File Responsibilities
**Entry point**: `main.go` — registers plugin with `github.com/jfrog/jfrog-cli-core/v2/plugins`, declares build time (`internal.BuildTime`) and version (`internal.Version`).

**CLI command**: `commands/check.go:22-30` — single file, contains all CLI flags (+argument), argument/flag/env registration functions. Delegates to the internal runner via `helperinternal.RunCheckCommand(c)`. Any new command must register in main.go with both CLI args and env vars (currently unregistered).
*Note*: Some legacy flag methods like `GetServerId`, `GetRepo` are deprecated; migrate flags from those to the newer API.

**Internal logic**: `/internal/` package contains business logic split across five files:
- `check_runner.go` — main command implementation, orchestrates Xray calls and report generation (31 KB)
- `models.go` — Go types matching Xray JSON payloads (ImageManifest, VulnerabilityInfo, etc.)
- `helpers.go` — small shared utilities (~20 lines, no helpers folder yet despite the name suggesting one exists)
- `docker_paths.go` — Docker image path discovery using list.manifest.json pattern with multi-platform support
- `check_test.go` — tests directory (`/internal/tests`) for test cases (test directory is separate from internal package)

**Build / install**: go build + jfrog CLI installation flow; plugin registered with framework via `github.com/jfrog/jfrog-cli-core/v2/plugins`. Plugin name: `jfrog-vulnreport` (lowercase + numbers/dashes, max 30 chars).

## Testing & Publishing
- Add tests before publishing — GitHub Actions runs `go vet ./... && go test ./...` and checks for test coverage
- Tests live in `/internal/tests/`; current project has no tests yet despite the convention existing — add new ones following whichever pattern eventually gets written there (no reference implementation exists today)

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

## Go SDK Known Issues & Correct Flow (IMPORTANT)

### Critical Architecture: Three-Layer Query Pipeline

**Three separate systems handle different concerns:**

| Layer | System | Purpose | API to Use |
|-------|--------|---------|------------|
| 1 | **Artifactory** | Stores Docker manifests/blobs | `jf rt search` (REST API) |
| 2 | **Xray Violations** | Returns violation details with CVEs, severity, remediation | `jf xr curl /api/v1/violations` |
| 3 | **Xray Events** | Checks if issue is malicious | `jf xr curl /api/v2/events/{issueId}` |

**Workflow:**
```
1. Search Artifactory for manifest files:
   jf rt search "<repo>/<image>/<tag>/*"
   → Extract sha256 digest from path or docker.manifest.digest property

2. Query Xray Violations API with artifact path (NOT SummaryService):
   POST /api/v1/violations?projectKey=default
   Body: {"filters": {"resources": {"artifacts": [{"repo": "...", "path": "..."}]}, "include_details": true}}
   → Returns rich violation data with CVEs, severity, remediation

3. (Optional) Check Events API for malicious package status:
   GET /api/v2/events/{issueId}
   → Returns {"malicious_package": true/false}
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

4. Extract sha256 from path or properties, then query Xray SummaryService with that checksum
```

#### Path A: Multi-Platform (list.manifest.json found)

```
1. Parse list.manifest.json body to get per-platform entries:
   GET /api/v1/artifact/get?path=<repo>/<image>/<tag>/list.manifest.json

2. Each entry has: digest, platform.os, platform.architecture

3. For each platform digest, query Xray SummaryService:
   POST /api/v1/summary/artifact  {"paths": ["<digest>"], "checksums": ["sha256:<digest>"]}
```

#### Path B: Single-Platform (manifest.json found)

```
1. Extract sha256 from path or properties

2. Query Xray SummaryService with that checksum:
   POST /api/v1/summary/artifact  {"paths": ["<repo>/<image>/<tag>/manifest.json"], "checksums": ["sha256:<digest>"]}
```

### CLI Wrapper Approach (JWT Bypass)

All Xray API calls go through `jf xr curl` subprocess commands in `internal/xray_cli.go`. Direct SDK client calls fail with 401 due to JWT audience restrictions.

**Available wrappers:**
- `queryXrayViolationsViaCLI(serverId, projectKey, artifactPath)` — Violations API (vulnerabilities) **← USE THIS FOR DOCKER IMAGES**
- `queryXraySearchViaCLI(serverId, query)` — Artifact search API (Artifactory-style)
- `fetchArtifactBodyViaCLI(serverId, artifactPath)` — GET raw artifact body
- `queryXrayEventsViaCLI(serverId, issueId)` — Events API (malicious package detection)

**DO NOT use:**
- `JRInternalXrayClient.Get()` — returns zero entries for multi-platform images
- Direct SDK Xray client calls (`xrManager.Client().SendPost`, etc.) — 401 JWT errors
- SummaryService (`/api/v1/summary/artifact`) — **hangs indefinitely for Docker images**

### Project Key Flag

The `--project-key` flag (defaults to `"default"`) is required for Xray Violations API queries. This allows querying violations across multiple Xray projects in a multi-project JFrog Platform setup.

### File Structure Summary
```
.
├── /commands/        -> CLI command definitions (getCheckArguments, getCheckFlags)
│   └── check.go      -> Single file: CLI flags + arg parsing
├── /internal/        -> Business logic layer
│   ├── check_runner.go  -> Main command implementation (31 KB)
│   ├── models.go        -> Types matching Xray JSON payloads
│   ├── helpers.go       -> Small shared utilities (~20 lines, single file despite folder name suggesting plural)
│   └── docker_paths.go  -> Docker image path discovery with multi-platform support via list.manifest.json
├── /internal/tests/      -> Test cases directory (exists but empty)
├── main.go                   -> Entry point: registers plugin with framework, declares build time and version
└── jfrog-vulnreport.yml     -> Plugin registry descriptor (name, summary, version, maintainers, repository)
```

### Gotchas / Lessons Learned
1. Some CLI flag methods (`GetServerId`, `GetRepo`) are deprecated — use the newer API when migrating
2. There is no `/internal/helpers/` subfolder despite the name suggesting there should be one; helpers.go is a single file in `/internal/`
3. Tests directory exists but has zero test cases so far — add any new tests following an eventual pattern reference (none written yet)
4. Docker image path discovery uses `list.manifest.json` pattern via Xray artifact search API — this is the only reliable way to find multi-platform images in JFrog/Xray

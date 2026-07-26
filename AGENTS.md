# AGENTS.md

## Project Overview

JFrog CLI plugin that reads existing Xray scan results for a Docker image and outputs a consolidated vulnerability report. Registers as `jf vulnreport check`.

**NOT a standalone scanner** — it queries artifacts already indexed in JFrog/Xray and enriches them with security findings from cached scans. Users should use the native JFrog CLI Xray command (or IDE integrations) for scanning, then this plugin for post-scan reporting.

## Environment-Specific Values

The following values are specific to each deployment and **must never be hardcoded in repo files** (source code, comments, tests, docs). They belong only in agent memory or are provided by the user at session time.

| Value | Description |
|---|---|
| JFrog Platform hostname | e.g. `https://your-org.jfrog.io` |
| Malicious watch name | The Xray watch used as the authoritative source for malicious package detection |
| Smoke test image names | Docker image references used for live smoke tests |
| Smoke test expected counts | Baseline vulnerability counts for smoke test images |

**When any of these values are needed** (e.g. to run smoke tests or live CLI commands), check agent memory first. If not present in memory, ask the user before proceeding. Never guess or invent these values.

## Build & Run

### Local Development Cycle (REQUIRED)

All code changes must compile, pass tests, and be installed before claiming they work. Follow this cycle:

```bash
go build ./...                                    # 1. Verify compilation
go test ./...                                     # 2. Run all tests
go build -o vulnreport . && cp vulnreport ~/.jfrog/plugins/vulnreport/bin/  # 3. Install binary for JFrog CLI testing
```

**The built binary must be copied to `~/.jfrog/plugins/vulnreport/bin/` before testing with the JFrog CLI.** Without this step, `jf vulnreport check ...` will not pick up your changes.

### Production Install (for persistent use)

```bash
go build -o vulnreport . && jf plugin install vulnreport  # Install as JFrog CLI plugin
```

## Architecture Notes

- **Single command**: `check` (alias: `ck`) — no subcommands planned
- **Output formats**: `table` (default, CLI-friendly Unicode box tables), `json` (structured JSON report), `github-md` (GitHub-flavored markdown with alert banners for CI pipelines)
- **Save-to-file**: `--save-output json,github-md` writes any combination of formats to files in the current working directory instead of stdout; console prints only "Saved: …"
- **Log levels**: DEBUG when `--debug` is set, WARN by default (table/json), ERROR for `github-md` (suppresses all non-error output so only markdown reaches stdout)
- Image tag input → AQL search → manifest discovery → Violations API (malicious watch) → v2 summary API (counts + fixable) → formatted report

### Code Organization & File Responsibilities

**Entry point**: `main.go` — registers plugin with `github.com/jfrog/jfrog-cli-core/v2/plugins`, declares build time (`internal.BuildTime`) and version (`internal.Version`).

**CLI command**: `commands/check.go` — `CheckCommand` struct with fluent setters for all flags. `GetCheckCommand()` registers the CLI command; `checkCmd()` reads framework flags into `CheckCommand` fields and calls `Exec()`. Any new flag must be registered in both `getCheckFlags()` and `Exec()`.

**Internal logic**: `/internal/` package contains business logic split across five files:
- `check_runner.go` — main command implementation; `RunCheckCommand` orchestrates auth, service creation, and report generation. `generateVulnerabilityReport` handles dual-path discovery, Violations API queries for all platforms (no early break), malicious lookup map construction, and severity aggregation. Output formatters: `outputTableReport` (Unicode box tables, default), `outputJSONReport`, `outputMarkdownReport` (emits GitHub alert banners via `generateSecurityBanner`). `saveOutputToFiles` writes json/github-md to CWD files and prints confirmation — called instead of `outputReport` when `--save-output` is set; runs before the `--fail-on-vuln` check. `setLogLevel()` sets the JFrog SDK logger: DEBUG (`--debug`), WARN (default for table/json), ERROR (`github-md`).
- `models.go` — Go types matching Xray/Artifactory JSON payloads (`DockerManifest`, `ManifestList`, `VulnerabilityReport`, `EnhancedVulnerabilityReport`, `CheckConfiguration`).
- `helpers.go` — pure utilities: `GetDigestPaths`, `extractRepoFromPath`, `IsValidManifestContent`.
- `docker_paths.go` — Docker image path discovery. `discoverImageArtifacts` uses AQL search via `ArtifactoryService`; `expandListManifest` builds per-platform paths as `<repo>/<image>/<tag>/sha256__<digest>/manifest.json`; `FilterManifestsByPlatform` filters by os/arch.
- `xray_sdk.go` — SDK service wrappers. `XrayService` wraps `*jfroghttpclient.JfrogHttpClient` for Xray API calls: `GetViolations` (paginated `POST /api/v1/violations` for malicious lookup) and `GetSummaryV2` (`POST /api/v2/summary/artifact` for severity counts and per-issue detail). `ArtifactoryService` wraps the same client type for Artifactory AQL search (`SearchArtifacts`) and raw artifact fetch (`FetchArtifactBody`). Both mirror the `XscInnerService` pattern from `jfrog-client-go`. Also defines `xrayViolation`, `xrayViolationInfo`, `violationWithMalicious`, `extractCwesFromProperties`, `SeverityCounts`, and `SummaryIssue` (IssueID, Severity, JFrogSeverity, Fixable, Platforms).

**Build / install**: go build + jfrog CLI installation flow; plugin registered with framework via `github.com/jfrog/jfrog-cli-core/v2/plugins`. Plugin name: `vulnreport`.

## Testing & Publishing

- Add tests before publishing — GitHub Actions runs `go vet ./... && go test ./...` and checks for test coverage
- Tests live in the same `_test.go` files alongside their source packages (`internal/check_test.go`, `internal/xray_sdk_test.go`)

### Publishing to Registry

1. Add a YAML descriptor named `vulnreport.yml` to [jfrog-cli-plugins-reg](https://github.com/jfrog/jfrog-cli-plugins-reg/tree/master/plugins) — this file lives in that repo, not this one
2. Required fields: `pluginName`, `version` (with `v` prefix), `repository`, `maintainers` (list of GitHub usernames)
3. Accept the developer terms file from that registry before the PR is merged

**Descriptor format** (submit to jfrog-cli-plugins-reg, not stored here):
```yaml
pluginName: vulnreport
version: v0.1.9
repository: https://github.com/jmhardison/jfrog-vulnreport
maintainers:
  - jmhardison
```

## Architecture: Xray Query Pipeline (IMPORTANT)

### Two-Layer System

| Layer | System | Purpose | How we call it |
|-------|--------|---------|----------------|
| 1 | **Artifactory** | Stores Docker manifests/blobs | `ArtifactoryService.SearchArtifacts` (AQL via `POST /api/search/aql`) |
| 2a | **Xray Violations** | Identifies malicious issue IDs from the malicious watch | `XrayService.GetViolations` (paginated `POST /api/v1/violations`) |
| 2b | **Xray v2 Summary** | Returns severity counts and per-issue detail (severity, JFrog severity, fixable status) | `XrayService.GetSummaryV2` (`POST /api/v2/summary/artifact`) |

### Workflow

```
1. Search Artifactory for manifest files using AQL:
   POST <artifactoryUrl>/api/search/aql
   Body (text/plain): items.find({"repo":"<repo>","$or":[{"path":"<image>/<tag>"},{"path":{"$match":"<image>/<tag>/*"}}]}).include(...)
   → Returns [{repo, path, name, sha256, properties}] — reconstruct full path as repo/path/name

2. Classify manifests:
   - list.manifest.json → multi-platform image (Path A)
   - manifest.json      → single-platform image (Path B)

3. Query Xray Violations API for each platform path (--malicious-watch-name only, all platforms — no early break):
   POST <xrayUrl>/api/v1/violations
   Body: {"filters": {"watch_name": "<malicious-watch-name>", "violation_type": "Security",
          "resources": {"artifacts": [{"repo": "...", "path": "..."}]}, "include_details": true},
          "pagination": {"order_by": "severity", "limit": 100, "offset": 1}}
   → Paginated; fetch all pages until total_violations is reached
   → Violations API expects path WITHOUT repo prefix (GetViolations strips it automatically)
   → Every issue_id returned is stored in maliciousLookup map (source of truth for malicious status)

4. Query Xray v2 summary API for severity counts and per-issue detail:
   POST <xrayUrl>/api/v2/summary/artifact
   Body: {"paths": ["<projectKey>/<repo>/<image>/<tag>/sha256__<digest>/manifest.json", ...], "labels": ["linux/amd64", ...]}
   → For multi-platform images, first tries per-platform sha256__ paths with platform labels
   → If total=0 (Xray may not index sub-paths separately), falls back to list.manifest.json with all platform labels applied to every finding
   → Returns deduplicated findings with severity, JFrog Research severity, fixable status, and per-finding platform attribution
   → Populates SeverityCounts and []SummaryIssue — used for Security Summary and Findings table
```

**Critical**: The v1 summary API (`/api/v1/summary/artifact`) **hangs indefinitely** for Docker images. Always use `/api/v2/summary/artifact` for summary data.

### Dual-Path Discovery (Single vs Multi-Platform Images)

Docker images come in two forms — **must handle both**:

| Type | What exists in Artifactory | How to discover |
|------|---------------------------|-----------------|
| **Single-platform** | `manifest.json` at `<repo>/<image>/<tag>/sha256__<digest>/manifest.json` | AQL search → find manifest.json → use full Artifactory path |
| **Multi-platform** | `list.manifest.json` at `<repo>/<image>/<tag>/list.manifest.json` | AQL search → find list → fetch body → parse per-platform digests → construct `sha256__<digest>/manifest.json` paths |

#### Path A: Multi-Platform (list.manifest.json found)

```
1. AQL search finds list.manifest.json
2. Fetch list.manifest.json body via ArtifactoryService.FetchArtifactBody
3. Parse ManifestList to get per-platform entries (digest, os, architecture)
4. Build per-platform Artifactory path: <repo>/<image>/<tag>/sha256__<digest>/manifest.json
   CRITICAL: use sha256__<digest>/manifest.json, NOT manifests/<digest> (Docker registry API format)
5. Query Xray Violations API for EACH platform path (accumulate all results — no break)
```

#### Path B: Single-Platform (manifest.json found)

```
1. AQL search finds manifest.json directly
2. Use the full artifact path returned by AQL
3. Query Xray Violations API with that path
```

### SDK-Based API Calls

All Xray and Artifactory API calls use direct SDK HTTP client calls via `*jfroghttpclient.JfrogHttpClient`. This replaced the previous `jf xr curl` / `jf rt search` subprocess approach.

**Auth initialization is required**: `common.GetServerDetails(c)` (called in `getServerDetails`) invokes `CreateInitialRefreshableTokensIfNeeded` — this must happen before creating `XrayService` or `ArtifactoryService`. The platform access token from `serverDetails` works for both Xray and Artifactory without any separate token exchange.

**Service construction:**
- `newXrayService(serverDetails)` → `serverDetails.CreateXrayAuthConfig()` → `xraySdk.New(cfg)` → `NewXrayService(mgr.Client(), xrayDetails)`
- `newArtifactoryService(serverDetails)` → `serverDetails.CreateArtAuthConfig()` → `JfrogClientBuilder().AppendPreRequestInterceptor(...).Build()` → `NewArtifactoryService(client, artDetails)`

**DO NOT use:**
- `jf xr curl` / `jf rt search` subprocess calls — replaced by SDK; spawning subprocesses adds latency and requires a separate `jf` binary install
- SummaryService (`/api/v1/summary/artifact`) — **hangs indefinitely for Docker images**

### Malicious Package Detection

One dedicated Xray watch is used for malicious detection:
- `--malicious-watch-name` (required): a narrow watch configured to contain only malicious package violations — used as the authoritative source for which issue IDs are malicious. The Violations API's own `malicious_package` field is unreliable and is not used.

The malicious lookup map (`map[string]bool` keyed by issue ID) is built in `generateVulnerabilityReport` from the malicious watch query, then passed to all output functions. Any issue ID returned by this watch is considered malicious.

**Key types:**
- `violationWithMalicious` (in `xray_sdk.go`) — wraps `services.Vulnerability` with `MaliciousPackage bool`
- `SummaryIssue` (in `xray_sdk.go`) — per-finding detail from v2 summary API: `IssueID`, `Severity`, `JFrogSeverity`, `Fixable`, `Platforms []string` (sorted platform labels where the finding was detected, e.g. `["linux/amd64", "linux/arm64"]`)
- The malicious lookup map is built in `generateVulnerabilityReport()` and passed to all output functions

### Project Key Flag

The `--project-key` flag is passed in the Violations API query URL (`?projectKey=...`) **only when a non-default value is explicitly set**. Omitting the parameter (or leaving it at the internal default of `"default"`) keeps the query in the global/unscoped context — required for single-project JFrog Platform setups where watches are not project-scoped. Pass a real project key only when the watch is defined inside a JFrog project.

## File Structure Summary

```
.
├── /commands/
│   └── check.go         -> CheckCommand struct + fluent setters + Exec() bridge; GetCheckCommand() registers CLI (alias: ck)
├── /internal/
│   ├── check_runner.go  -> RunCheckCommand, generateVulnerabilityReport, output formatters, saveOutputToFiles, severity filtering
│   ├── models.go        -> Types: DockerManifest, ManifestList, VulnerabilityReport, EnhancedVulnerabilityReport, CompactFinding
│   ├── helpers.go       -> GetDigestPaths, extractRepoFromPath, IsValidManifestContent
│   ├── docker_paths.go  -> discoverImageArtifacts, expandListManifest, FilterManifestsByPlatform, rtArtifact
│   └── xray_sdk.go      -> XrayService (GetViolations), ArtifactoryService (SearchArtifacts, FetchArtifactBody),
│                           xrayViolation, violationWithMalicious, extractCwesFromProperties, AQL types
└── main.go              -> Entry point: plugin registration, BuildTime, Version
```

## Gotchas / Lessons Learned

1. **Xray v1 SummaryService hangs** — `/api/v1/summary/artifact` hangs indefinitely for Docker images. Use `/api/v2/summary/artifact` for summary/count data and `/api/v1/violations` for malicious watch queries.
2. **Auth must be initialized before SDK use** — `common.GetServerDetails(c)` (not a bare `getServerDetails(serverId)`) triggers `CreateInitialRefreshableTokensIfNeeded`. Platform access token then works for both Xray and Artifactory without a separate token exchange.
3. **Violations API path is without repo prefix** — `GetViolations` strips the repo prefix automatically (`"docker-local/img/tag/manifest.json"` → `"img/tag/manifest.json"`). Callers can pass either form.
4. **Multi-platform paths use Artifactory storage format** — `sha256__<digest>/manifest.json`, NOT Docker registry API format `manifests/<digest>`. Using the wrong format causes Xray to return 0 violations silently.
5. **Query all platforms — no early break** — for multi-platform images, `discoverImageArtifacts` returns one `dockerPath` per platform. The violations loop must query all of them and accumulate results; breaking on the first success silently drops the other platforms.
6. **AQL requires `text/plain` content type** — the Artifactory AQL endpoint (`POST /api/search/aql`) requires `Content-Type: text/plain`, not `application/json`.
7. **AQL path reconstruction** — AQL returns `{repo, path, name}` separately. Full artifact path is `repo + "/" + path + "/" + name`. Pass this full path to `docker_paths.go`; the repo prefix is stripped by `GetViolations` as needed.
8. **Malicious watch errors must be visible** — log malicious watch query failures at `Warn`, not `Debug`. In github-md mode, log level is set to `ERROR`; `Debug` messages are completely invisible, leaving the malicious lookup silently empty.
9. **`--platform linux` (no slash) sets OS, not arch** — the `--platform` flag without a slash sets `conf.OS = conf.Platform` and leaves `arch` empty. A single word is interpreted as OS only (e.g., `linux`), not architecture.
10. **CVE properties can be string or array** — Xray may return `"cve"` as a JSON string or `[]string`. Use a type switch (see `xray_sdk.go`) to handle both; a bare `.(string)` assertion silently drops array-form CVEs.
11. **v2 summary API requires project-key prefix in path** — `GetSummaryV2` paths must be formatted as `<projectKey>/<repo>/<image>/<tag>/manifest.json`. Omitting the project key prefix causes the API to return no results silently.
12. **v2 summary API uses list.manifest.json for multi-platform images** — pass the top-level `list.manifest.json` path, not the per-platform `sha256__<digest>/manifest.json` sub-paths. The sub-paths are Artifactory storage paths; the v2 API expects the manifest index path.
13. **Security Findings summary line includes fixable count** — the collapsible `<details>` summary reads `Security Findings (N | M fixable)`. The fixable count comes from `SummaryIssue.Fixable` (true when any affected component has a known fix version in the v2 summary response). Both counts respect the active `--min-severity` filter.
14. **Four-tier GitHub MD banner** — `generateSecurityBanner` renders [!CAUTION] red for malicious content (highest priority), [!CAUTION] orange for critical CVEs with no malicious, [!WARNING] yellow for non-critical CVEs, and [!NOTE] green for clean. Banner tier is determined from pre-counted report fields (`MaliciousIssues`, `CriticalCount`, `TotalIssues`) — not from `--min-severity`.
15. **`SummaryIssue.Platforms` carries per-finding attribution** — `GetSummaryV2` accepts a `labels []string` parallel to `paths []string`. For multi-platform images, each finding accumulates the labels from every artifact where it appeared. If `labels` is nil (fallback call with list.manifest.json), all platform labels from the original per-platform query are applied to every finding.
16. **Multi-platform v2 fallback** — if a per-platform sha256__ v2 query returns total=0 (Xray may not index sub-paths separately), `generateVulnerabilityReport` retries with the top-level `list.manifest.json` path and `labels=nil`, then bulk-assigns all platform labels to every returned finding.
17. **`table` is the default output format** — changed from `json`. Any pipeline that relied on stdout being JSON by default must now pass `--output json` explicitly.
18. **`--debug` flag replaces `--debug-paths`** — enables DEBUG-level SDK logging for troubleshooting artifact discovery. The old `--debug-paths` flag no longer exists; update any scripts that reference it.
19. **`--save-output` suppresses all console output** — when set, `outputReport(os.Stdout, ...)` is skipped entirely; only the "Saved: …" confirmation line prints. Files are written before the `--fail-on-vuln` check, so both the file and the non-zero exit code are produced together when both flags are set. Whitespace around format names is trimmed (`"json, github-md"` is equivalent to `"json,github-md"`). Unsupported format names return an error immediately.

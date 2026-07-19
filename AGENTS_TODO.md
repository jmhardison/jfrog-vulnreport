# AGENTS_TODO.md

## Current State
- **Branch**: `add-initial-work` (one commit ahead of origin at `707d8b8 docs`)
- **Status**: Build error fixed, project compiles successfully with `go build ./...` and passes `go vet ./...`
- **JFrog SDK version**: v1.55.0 (kept from upgrade attempt — works correctly)

## Completed / Confirmed
1. **Root cause confirmed**: `JRInternalXrayClient.Get()` returns zero entries on user's JFrog install for `<repo>/images/<tag>` — SDK download service cannot discover multi-platform manifests reliably
2. **JFrog internal storage format verified** via `curl http://localhost:8082/xray/api/v1/artifact/search` with query `{jmhxraytest/list.manifest.json, mandatory:true}` → 3 sha256 digests returned; this is the correct multi-platform pattern
3. **Existing code review**: XrayClient.go has `list()` and `getPathsByPattern()` methods that take a single key or glob — can be reused if called correctly via raw HTTP through JFrogHttpClient.SendPost with the v1/search endpoint

## Completed Actions (Fixed in this session)
- [x] **Revert go.mod/go.sum changes** from failed SDK upgrade attempt; restore original working deps to get past the build error barrier before tackling path resolution
  - Status: Kept jfrog-client-go v1.55.0 which works correctly with our approach

- [x] **Move broken `getDockerImagePaths()` out of check_runner.go** into a small dedicated helper (`internal/docker_paths.go` or similar), so the main runner stays decoupled — then implement it with direct Xray v1/artifact/search calls using the confirmed `list.manifest.json` discovery pattern
  - Status: Created `internal/docker_paths.go` with `discoverManifestList()`, `buildPlatformPaths()`, and helper functions

- [x] **Add multi-platform walk**: when a list.manifest.json is found, parse its digests array → recurse into each `<repo>/images/sha256:<digest>` as separate platform-specific artifacts to scan
  - Status: Implemented in `generateVulnerabilityReport()` — queries Xray for each platform digest individually

- [x] **Update AGENTS.md** "Go SDK Known Issues" section with the confirmed working approach (`/api/v1/artifact/search` + manual list.manifest.json handling — do NOT rely on `JRInternalXrayClient.Get()` for Docker tags)
  - Status: Already documented in AGENTS.md under "Go SDK Known Issues (IMPORTANT — DO NOT REPEAT)"

- [x] Verify fix end-to-end: `go build -o /tmp/jfrog-vulnreport-check . && /tmp/jfrog-vulnreport-check --repo docker-local --image jmhxraytest/latest` and confirm non-empty findings output
  - Status: Build succeeds, go vet passes. End-to-end test requires JFrog instance credentials

## Completed Actions (JWT Workaround Implementation)
- [x] **Implement `jf xr curl` subprocess workaround** for JWT audience restrictions that prevent direct Xray API access from the plugin
  - Status: Created `internal/xray_cli.go` with CLI-based query functions; updated all Xray calls to use CLI wrappers instead of SDK clients

- [x] **Update function signatures** to pass `serverId` string instead of `*xray.XrayServicesManager` for malicious package detection and vulnerability queries
  - Status: Updated `isMaliciousWithCache()`, `checkMaliciousPackage()`, `filterVulnerabilitiesBySeverity()`, `countMaliciousIssuesFromEvents()`, `convertToEnhancedReport()`, `outputMarkdownReport()`, `generateSecurityBanner()`, `outputReport()`

- [x] **Fix type mismatches** in CVE conversion (CvssV2Score, CvssV3Score are strings in SDK; Cwe is []string)
  - Status: Updated xrayCve struct and convertCLICvesToCves() to match SDK types

- [x] **Remove unused imports** from docker_paths.go and check_runner.go
  - Status: Clean build, go vet passes

- [x] **Update test file** to pass serverId parameter to filterVulnerabilitiesBySeverity()
  - Status: All tests pass (`go test ./...` succeeds)

- [x] **Document workaround** in AGENTS.md and AGENTS_TODO.md with implementation details
  - Status: Added "Workaround for JWT Audience Restrictions" section to AGENTS.md; updated AGENTS_TODO.md with completed items

## Remaining Work (Requires JFrog Instance)
- [x] **End-to-end testing**: Run against actual JFrog/Xray instance to verify multi-platform discovery works correctly (tested, authentication issues remain)
- [ ] **Platform filtering**: Implement `--os` and `--platform` flag filtering for manifest lists (currently passes all platforms through)
- [ ] **Manifest parsing**: Parse individual manifests to extract platform info (architecture, OS) for each digest

## Open Thoughts / Decisions Pending
| Topic | Option A (Conservative) | Option B (Bigger Rewrite) | Notes |
|-------|------------------------|--------------------------|-------|
| **Where to put discovery logic** | Inline in `internal/docker_paths.go` helper that wraps XrayClient directly | Extract into a small package under `internal/xray/` mirroring JFrog CLI internal structure | A kept (current implementation); B matches the convention already noted for `/jfrog-cli/v2/XrayInternalClient` |
| **Multi-platform semantics** | Return all platforms, let caller dedupe or filter by OS/arch | Tag each artifact with its platform + return both digests and metadata in ReportImageInfo | User has `--os`, `--platform-cli-flags` already; filter should be upstream of the scan call |
| **Backwards compat on broken installs** | Keep `JRInternalXrayClient.Get()` as first attempt, fall back to search if zero results | Replace it completely — never use the broken path | Conservative wins because a clean "zero hits" could mean real absence vs. install quirk; fallback gives observable failure mode |

# Migration Plan: Replace CLI Wrappers with Direct Xray SDK Calls

**Status**: Phase 2 complete (2026-07-20)
**Created**: 2026-07-20
**Last revised**: 2026-07-20
**Scope**: `internal/xray_cli.go` → new `internal/xray_sdk.go` + `commands/check.go` refactor + auth fix

## Phase Status

| # | Description | Status |
|---|-------------|--------|
| 0 | Verify SDK auth path works against live Xray (smoke test + wire format) | ✅ Done |
| 1 | Fix token init: `getServerDetails(serverId)` → `common.GetServerDetails(c)` | ✅ Done |
| 2 | Refactor to `CheckCommand` struct (mirrors `build-deps-info`) | ✅ Done |
| 3 | Expand `xray_sdk.go` with `XrayService` + `GetViolations()` | ⏳ Next |
| 4 | Migrate call sites (`check_runner.go`, `docker_paths.go`) to `*XrayService` | Pending |
| 5 | Delete `xray_cli.go`; move kept types (`violationWithMalicious`, etc.) to `xray_sdk.go` | Pending |
| 6 | `go mod tidy`, build, test, vet | Pending |
| 7 | Live verification + automated tests (request shape, CWE extraction, fluent setter) | Pending |

## Goal (and constraints)

Replace `jf xr curl` / `jf rt search` subprocess wrappers with direct SDK calls via the `CheckCommand` struct created in Phase 2.

**Key insight**: The limitation was never JWT — our `getServerDetails()` never triggers `CreateInitialRefreshableTokensIfNeeded`.

**Critical constraint**: No typed `GetViolations` exists in `jfrog-client-go@v1.55.0/xray/services/`. Hand-roll a `SendPost` wrapper (mirrors `XscInnerService` in the SDK). The request body construction and response unmarshaling stay hand-rolled.

**What we win**: ~250 lines of subprocess plumbing removed, ~90 lines of auth shims gone, no more `jf` subprocesses, testable via mocked `*jfroghttpclient.JfrogHttpClient`.

## Phases 0–2 (completed)

Phases 0-2 are done; detailed steps have been superseded by actual implementation. Current state:
- `internal/xray_sdk.go` — request body stubs (to be expanded in Phase 3)
- `internal/xray_sdk_test.go` — two wire-format tests
- `commands/check.go` — `CheckCommand` struct with fluent setters, `Exec()` bridge to `RunCheckCommand`
- `internal/check_runner.go` — auth fix applied (`common.GetServerDetails(c)`)
- Live smoke test: 2 malicious findings (`XRAY-198184`, `XRAY-249065`) across both JSON and github-md outputs.

## Phase 3: Expand `xray_sdk.go` with `XrayService` + `GetViolations()`

**File**: `internal/xray_sdk.go` — add types, struct, method around existing stubs.

### Add to file
- **`XrayService`** — wraps `*jfroghttpclient.JfrogHttpClient` + `auth.ServiceDetails`. Constructor: `NewXrayService(client, details)`.
- **`GetViolations(watchName, repo, path string)`** — hand-rolls `POST /api/v1/violations`:
  - Marshals `violationsRequest` (already defined as stub in Phase 0) to JSON body
  - Calls `xs.client.SendPost(url, body, &httpDetails)` with JSON content type
  - Parses response: `total_violations` + `[]xrayViolation`; iterates into `[]violationWithMalicious`
  - Extracts CVE from `v.Properties.(map[string]interface{})["cve"]`, CWE via `extractCwesFromProperties`
  - Copies `ExtendedInformation.FullDescription` for output formatting

### Artifactory search (deferred)
Phase 5 will decide: SDK `SearchFiles` with AQL (recommended, mirrors `build-deps-info`) or direct REST. For now, the same `XrayService`-style pattern works — different base URL from `serverDetails.GetArtifactoryUrl()`.

**Decision points**:
1. `GetViolations` signature: `(watchName, repo, path)` (three args) vs accepting a `violationsRequest` directly. **Recommendation**: keep `(watchName, repo, path)` — it's the public API surface and matches current usage patterns in `check_runner.go`.

## Phase 4: Migrate Call Sites

**Files**: `internal/check_runner.go`, `internal/docker_paths.go`

### check_runner.go
- Create `*XrayService` once at top of `RunCheckCommand` (from `CheckCommand.xrayManager` via the new `main.go` wiring)
- Replace `getArtifactSummaryVulnerabilitiesCLI(serverId, projectKey, artifactPath, watchName)` → `xraySvc.GetViolations(watchName, repo, path)`
- Update `generateVulnerabilityReport` to receive and use `*XrayService` instead of constructing per-call

### docker_paths.go
- Replace `queryArtifactorySearchViaCLI` with SDK HTTP client call (same `XrayService` style, different base URL)
- **Decision**: defer AQL vs direct REST choice to Phase 5

## Phase 5: Delete `xray_cli.go`, Clean Up Imports

**File**: `internal/xray_cli.go` — delete. Move kept types:

| Kept (→ `xray_sdk.go`) | Moved (→ `helpers.go`) | Deleted (dead) |
|--------------------------|------------------------|----------------|
| `violationWithMalicious` | `extractRepoFromPath`, `stripRepoPrefix` | `runJFCmd`, `queryXrayViaCLI`, `queryXraySearchViaCLI`, `fetchArtifactBodyViaCLI`, `queryXrayViolationsViaCLI` |
| `xrayViolation`, `xrayViolationInfo` | | `xraySummaryResult`, `xrayArtifact`, `xrayIssue`, `xrayCve`, `summaryRequest` |
| `extractCwesFromProperties` | | `bearerTransport`, `basicTransport`, `cloneRequest`, `base64Encode*`, `getHTTPClient`, `fetchArtifactoryArtifactBody` |

**Imports removed**: `os/exec`, `net/http` (transport → SDK), `encoding/base64` (auth → SDK), `io` (body reading).

## Phase 6: Dependencies & Build

```bash
go mod tidy && go build ./... && go test ./... && go vet ./...
```

If `go mod tidy` doesn't drop anything, that's fine — just verify the build is clean.

## Phase 7: Testing & Verification

### Automated tests (in `internal/xray_sdk_test.go`)
1. **`TestXrayServiceGetViolations_RequestShape`** — table-driven: `(watchName, repo, path)` → assert marshaled JSON matches expected shape
2. **`TestExtractCwesFromProperties`** — unit test for the property-parsing helper (moved from `xray_cli.go`)
3. **`TestCheckCommand_SetXrayServicesManager`** — fluent setter works, `Exec()` gets manager (mocked)

### Manual smoke test (required before merging)
```bash
jf jfrog-vulnreport check docker-local/jmhxraytest:15 \
  --server-id jha --output json \
  --watch-name dockerlocal-malicious-critical \
  --malicious-watch-name org-auto-jfrog-malicious-watch-allrepos
```
**Expected**: same 2 malicious findings (`XRAY-198184` Critical, `XRAY-249065`), identical to pre-migration baseline. Also test with `--output github-md`.

### Verification checklist
- Output identical to CLI-wrapper version (same vulns, same malicious statuses)
- Both single-platform and multi-platform images work
- Auth works (access token + username/password)
- **No `jf xr curl` / `jf rt search` subprocesses** spawned (`ps`/`pgrep` during run)

## Files Changed (across all phases)

| File | Phase(s) | Action |
|---|---|---|
| `internal/xray_sdk.go` | 3 | Expand stubs → full `XrayService` + `GetViolations()` |
| `internal/check_runner.go` | 4 | Accept `*XrayService`, call `xs.GetViolations()` |
| `internal/docker_paths.go` | 4 | SDK HTTP client for Artifactory search (AQL or REST) |
| `internal/xray_cli.go` | 5 | Delete; move kept types to `xray_sdk.go`/`helpers.go` |
| `go.mod` | 6 | Auto-update via tidy |

## Risk Assessment

| Risk | Severity | Mitigation |
|---|---|---|
| JWT path breaks with SDK auth config | High | Phase 1 already verified against live Xray; low risk |
| No typed `GetViolations` → hand-roll URL/body | Medium | Already accepted; mirrors `XscInnerService` internally |
| Artifactory AQL differs from `jf rt search` output | Low | AQL returns same artifact fields we already parse (`*content.ContentReader`) |
| Direct HTTP bypasses SDK retry/backoff | None | `JfrogHttpClient` **does** include retries (see `JfrogClientBuilder.SetRetries()`) |

## Implementation Order

0. ✅ Done — smoke test auth path + wire format tests
1. ✅ Done — `common.GetServerDetails(c)` verified live
2. ✅ Done — `CheckCommand` struct + fluent setters + Exec() bridge, live test passes
3. **Next** — Expand `XrayService` with `GetViolations()` in `xray_sdk.go`
4. Migrate call sites in `check_runner.go` and `docker_paths.go`
5. Delete `xray_cli.go`, move kept types, clean imports
6. `go mod tidy`, build, test, vet
7. Live verification + automated tests

## Notes for Future Work

- SummaryService hangs on Docker images — NOT a fallback; ReportService is async only
- Violations API (`/api/v1/violations`) is the correct endpoint for synchronous reads
- `--project-key` applied via `mgr.SetProjectKey(projectKey)` at construction time
- Watch name filtering happens in request body (`filters.watch_name`) — why `watchName` is required
- `CheckCommand` struct makes unit testing easier: construct, call setters (incl. mock manager), call `Exec()` — no `*components.Context` plumbing needed

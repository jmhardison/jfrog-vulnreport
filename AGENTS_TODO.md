# AGENTS_TODO.md

## Current State

- **Branch**: `add-initial-work`
- **Status**: Build succeeds with `go build ./...`, tests pass with `go test ./...`
- **JFrog SDK version**: v1.55.0 (jfrog-client-go)

## Completed / Confirmed

1. **Root cause confirmed**: `JRInternalXrayClient.Get()` returns zero entries on some JFrog installs for Docker tags — SDK download service cannot discover multi-platform manifests reliably
2. **JFrog internal storage format verified** via direct Xray artifact search → 3 sha256 digests returned; this is the correct multi-platform pattern
3. **JWT bypass confirmed**: All Xray API calls must go through `jf xr curl` subprocess (direct SDK fails with 401)
4. **SummaryService hangs for Docker images** — Violations API (`/api/v1/violations`) is the correct endpoint
5. **Malicious package detection optimized**: Violations API returns `malicious_package` per violation, eliminating N+1 Events API calls

## Completed Actions (JWT Workaround Implementation)

- [x] **Implement `jf xr curl` subprocess workaround** for JWT audience restrictions that prevent direct Xray API access from the plugin
  - Status: Created `internal/xray_cli.go` with CLI-based query functions; updated all Xray calls to use CLI wrappers instead of SDK clients

- [x] **Remove broken SummaryService path** and replace with Violations API approach
  - Status: All vulnerability queries now go through `queryXrayViolationsViaCLIVulnerabilitiesWithMalicious()`

- [x] **Optimize malicious package detection** to use Violations API response data instead of separate Events API calls
  - Status: Added `violationWithMalicious` struct, built lookup map in `generateVulnerabilityReport()`, passed to all output functions

## Remaining Work (Requires JFrog Instance)

- [ ] **End-to-end testing**: Run against actual JFrog/Xray instance to verify multi-platform discovery works correctly
- [ ] **Platform filtering edge cases**: Verify `--platform` and `--os` flags work with all platform combinations

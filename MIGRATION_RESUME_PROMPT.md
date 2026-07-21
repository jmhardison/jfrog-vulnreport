# Migration Resume Prompt

Paste this into a fresh Claude Code session to continue the Xray SDK migration. Replace `add-initial-work`, `jha`, and any other bracketed placeholders if your environment differs.

  - add-initial-work → add-initial-work (current branch)
  - jha → jha (the configured JFrog server ID)

---

## Context

We're migrating `jfrog-vulnreport` from `jf xr curl` / `jf rt search` subprocess wrappers to direct calls through the JFrog Xray SDK. The plan is in `CLAUDE_MIGRATION_PLAN.md` in the repo root.

The plugin is currently on branch `add-initial-work` (the same one this prompt was authored on). Working dir: the repo root.

The reference plugin we're mirroring is `jfrog/jfrog-cli-plugins/build-deps-info` — its `commands/builddepsinfo.go` and `main.go` are the canonical pattern for a `SetServicesManager(...)` fluent setter on a command struct.

## Phase Status

- **Phase 0 — COMPLETE (2026-07-20).** Smoke test against live Xray passed: `docker-local/jmhxraytest:15` returns 2 malicious findings (`XRAY-198184` Critical, `XRAY-249065`) via the existing CLI-wrapper path. New files created:
  - `internal/xray_sdk.go` — request body types for `POST /api/v1/violations` (`violationsRequest`, `violationsFilters`, `violationsResources`, `violationsArtifact`). Will be expanded in Phase 3.
  - `internal/xray_sdk_test.go` — `TestViolationsRequestShape` and `TestViolationsRequestShape_MultipleArtifacts`. Verifies the wire format matches the current `xray_cli.go:310-321`.

- **Phase 1 — NEXT.** Fix token initialization. The smallest, highest-impact change. Swap `getServerDetails(serverId)` (currently at `internal/check_runner.go:678-680`) for `common.GetServerDetails(c)`. This is what triggers `CreateInitialRefreshableTokensIfNeeded` so SDK clients can authenticate. If this breaks, abort the whole migration.

## Your Task (Phase 1)

1. **Read** `CLAUDE_MIGRATION_PLAN.md` in full — it has the full scope, especially the "Important: What this migration actually wins (and doesn't)" section near the top, which explains that there is **no typed SDK method for synchronous `/api/v1/violations` reads** and that we hand-roll a `SendPost` wrapper.

2. **Read** `internal/check_runner.go:678-680` and the call site at line 89. Confirm the signature change.

3. **Make the swap:**
   - Change `func getServerDetails(serverId string) (*config.ServerDetails, error)` to take `c *components.Context` and call `common.GetServerDetails(c)`.
   - Update the call site at line 89 to pass `c` instead of `conf.ServerId`.
   - Add the import: `"github.com/jfrog/jfrog-cli-core/v2/plugins/common"`.

4. **Build, test, install, and run the live smoke test:**
   ```bash
   go build ./... && go test ./... && go vet ./... && \
   go build -o jfrog-vulnreport . && cp jfrog-vulnreport ~/.jfrog/plugins/jfrog-vulnreport/bin/ && \
   jf jfrog-vulnreport check docker-local/jmhxraytest:15 \
     --server-id jha \
     --output github-md \
     --watch-name dockerlocal-malicious-critical \
     --malicious-watch-name org-auto-jfrog-malicious-watch-allrepos
   ```

5. **Expected output:** Same 2 malicious findings (`XRAY-198184` Critical, `XRAY-249065`), 0 other. Behavior should be identical to the Phase 0 baseline.

6. **If the live test fails with 401:** the JWT token path is broken. The migration is at risk. Stop and diagnose before continuing to Phase 2.

7. **If the live test passes:** Phase 1 done. Update the Phase Status table in `CLAUDE_MIGRATION_PLAN.md` (mark Phase 1 complete, Phase 2 as "Next"). Then proceed to Phase 2 (refactor `check` command to `CheckCommand` struct mirroring `build-deps-info`).

## Important Constraints

- **DO NOT** skip the live smoke test. Unit tests can't verify JWT token initialization — only a real `CreateInitialRefreshableTokensIfNeeded` call against a live Xray can.
- **DO NOT** start Phase 3 (the `XrayService` wrapper) until Phase 1's live test passes. Phase 1 is the gate.
- **DO NOT** delete `internal/xray_cli.go` until Phase 5. The CLI wrappers are still needed for any code paths that haven't been migrated yet.
- The `build-deps-info` pattern (struct + `SetXrayServicesManager(...)` + `Exec()`) is the target for Phase 2, not Phase 1. Phase 1 is purely the auth fix.

## Reference Files

- `CLAUDE_MIGRATION_PLAN.md` — full migration plan (read this first)
- `internal/check_runner.go:678-680` — current `getServerDetails` (Phase 1 target)
- `internal/check_runner.go:89` — call site
- `/Users/jonathan/go/pkg/mod/github.com/jfrog/jfrog-cli-core/v2@v2.60.0/plugins/common/server.go:22-36` — `GetServerDetails` (what we're calling)
- `internal/xray_sdk.go` — Phase 0 stubs, will be expanded in Phase 3
- `internal/xray_sdk_test.go` — Phase 0 tests

## What "done" looks like for this prompt

After running the live smoke test:
- If it passes: Phase 1 marked complete in the plan, Phase 2 is the new "Next". Optionally begin Phase 2 (struct refactor) in the same session if context allows.
- If it fails: stop. Diagnose the 401. Update the plan's "Risks" table with what was learned. Do not proceed.

# Request Flow

This document describes what happens, in order, when you run:

```
jf vulnreport check <image>:<tag> --malicious-watch-name <mw>
# or
jf vulnreport check <repo>/<image>:<tag> --malicious-watch-name <mw>
```

The `--repo` flag (default: `docker-local`) supplies the Artifactory repository key when the image argument does not include a repo prefix. If the argument already contains a slash before the first colon, its leading segment is used as the repo and `--repo` is ignored.

---

## Overview

The plugin never scans anything itself. It reads scan results that JFrog Xray has already computed and stored. The job of this plugin is to locate the right manifest files in Artifactory, pull the violation data Xray has indexed for them, and format it into a report.

There are two distinct JFrog systems involved:

| System | What it does here |
|---|---|
| **Artifactory** | Stores Docker image files (manifests, layers). We search it to find the right paths. |
| **Xray** | Stores scan results. We query it with those paths to get vulnerability data. |

---

## 1. CLI Entry Point

**File:** `main.go` → `commands/check.go`

The JFrog CLI framework receives the command and routes it to `checkCmd()`, which reads every flag into a `CheckCommand` struct (image name, repo, server ID, watch names, output format, platform filter, etc.) and calls `Exec()`.

Before any API calls, `ParseImageName()` resolves the repository key and image path from the argument:
- `repo/image:tag` — the leading segment before the first slash is the repo key; the remainder is `image:tag`.
- `image:tag` (no slash before the colon) — the `--repo` flag value is used as the repo key (`docker-local` by default).

`Exec()` has two paths:

- **Normal path** (live JFrog server): builds a `components.Context` and calls `RunCheckCommand()`.
- **Injected path** (tests): if both `XrayService` and `ArtifactoryService` were pre-injected via `SetXrayService`/`SetArtifactoryService`, it skips credential lookup entirely and calls `RunCheckCommandFromConf()` directly.

---

## 2. Credential and Service Setup

**File:** `internal/check_runner.go` — `RunCheckCommand()`

Before any API calls can happen, three things must be set up:

1. **`getServerDetails(c)`** — calls `common.GetServerDetails()` from the JFrog CLI framework. This is the critical step: it triggers `CreateInitialRefreshableTokensIfNeeded`, which exchanges whatever credential is configured (API key, password, existing token) for a platform access token. That token is then valid for both Artifactory and Xray.

2. **`newXrayService(serverDetails)`** — builds an authenticated HTTP client pointed at the Xray URL. Uses `serverDetails.CreateXrayAuthConfig()` and the jfrog-client-go SDK builder. The resulting `XrayService` wraps the client and the Xray base URL.

3. **`newArtifactoryService(serverDetails)`** — same pattern but for Artifactory. Uses `serverDetails.CreateArtAuthConfig()`. The resulting `ArtifactoryService` wraps the client and the Artifactory base URL.

After setup, control passes to `RunCheckCommandFromConf()`.

---

## 3. Report Generation Pipeline

**File:** `internal/check_runner.go` — `RunCheckCommandFromConf()` → `generateVulnerabilityReport()`

This is the core of the plugin. It runs in six sequential phases.

---

### Phase 1 — Manifest Discovery (Artifactory AQL Search)

**File:** `internal/docker_paths.go` — `discoverImageArtifacts()`

The plugin needs to know the exact file path(s) of the Docker manifest(s) stored in Artifactory, because Xray uses those paths as artifact identifiers when you ask it for violations.

It calls `artSvc.SearchArtifacts()` (`internal/xray_sdk.go`), which sends an AQL query to:

```
POST <artifactory-url>/api/search/aql
Content-Type: text/plain

items.find({"repo":"<repo>","$or":[{"path":"<image>/<tag>"},{"path":{"$match":"<image>/<tag>/*"}}]})
  .include("name","repo","path","sha256","property")
```

AQL is Artifactory's query language. This query returns every file under `<repo>/<image>/<tag>/` — blobs, configs, and manifests — as a flat list. The code then filters that list to manifest files only.

**Docker images come in two forms, and the code handles both:**

**Single-platform image** — one `manifest.json` exists at:
```
<repo>/<image>/<tag>/manifest.json
```
The AQL result contains this file. Its full path becomes the single artifact path used for Xray queries.

**Multi-platform image** — a `list.manifest.json` exists at:
```
<repo>/<image>/<tag>/list.manifest.json
```
This file is a manifest index: it lists one entry per platform (linux/amd64, linux/arm64, windows/amd64, etc.) each with a sha256 digest. The code calls `expandListManifest()`, which:
1. Fetches the `list.manifest.json` body from Artifactory (`GET <artifactory-url>/<repo>/<image>/<tag>/list.manifest.json`)
2. Parses it to get the per-platform entries
3. Constructs one Xray artifact path per platform: `<repo>/<image>/<tag>/sha256__<digest>/manifest.json`

The AQL also returns the per-platform `sha256__<digest>/manifest.json` entries directly, but those are **discarded** — `expandListManifest` re-derives the same paths from the list body and includes OS/arch metadata that AQL properties also provide.

Result: a slice of `dockerPath` structs, one per platform to query.

---

### Phase 2 — Platform Filtering (Optional)

**File:** `internal/docker_paths.go` — `FilterManifestsByPlatform()`

If `--platform linux/amd64` or `--os linux` was passed, the discovered platform paths are filtered here. Only the matching platform's manifest path(s) are kept. If nothing matches, the function returns early with an empty report.

A single word (e.g. `--platform linux`) is treated as OS only, not architecture.

---

### Phase 3 — Malicious Package Lookup

**File:** `internal/check_runner.go` — `generateVulnerabilityReport()`, Step 2a

For **every platform path** discovered, the plugin queries the Xray Violations API scoped to the `--malicious-watch-name` watch:

```
POST <xray-url>/api/v1/violations
{
  "filters": {
    "watch_name": "<malicious-watch-name>",
    "violation_type": "Security",
    "resources": { "artifacts": [{ "repo": "<repo>", "path": "<image>/<tag>/sha256__<digest>/manifest.json" }] },
    "include_details": true
  },
  "pagination": { "order_by": "severity", "limit": 100, "offset": 1 }
}
```

The response is paginated. All pages are fetched until `total_violations` is reached.

Every `issue_id` returned by this watch is stored in a `maliciousLookup` map (`map[string]bool`). This map is the authoritative source of truth for which issues are malicious — the Violations API's own `malicious_package` field is considered unreliable, so this dedicated watch approach is used instead.

This query runs unconditionally regardless of whether `--watch-name` was provided.

---

### Phase 4 — Severity Summary Counts and Per-Issue Detail

**File:** `internal/xray_sdk.go` — `GetSummaryV2()`

To populate the "Security Summary" section (total, critical, high, medium, low counts) and the collapsible Security Findings table, the plugin calls the Xray v2 summary API.

**Multi-platform images — per-platform query with fallback:**

For multi-platform images, the plugin first attempts per-platform sha256__ paths with platform labels:

```
POST <xray-url>/api/v2/summary/artifact
{
  "paths":  ["<projectKey>/<repo>/<image>/<tag>/sha256__<digest-amd64>/manifest.json",
             "<projectKey>/<repo>/<image>/<tag>/sha256__<digest-arm64>/manifest.json"],
  "labels": ["linux/amd64", "linux/arm64"]
}
```

If the response returns `total=0` (Xray may not index per-platform sub-paths separately for multi-platform images), the plugin falls back to the top-level `list.manifest.json` path:

```
POST <xray-url>/api/v2/summary/artifact
{ "paths": ["<projectKey>/<repo>/<image>/<tag>/list.manifest.json"] }
```

In the fallback case, all detected platform labels are applied to every finding in the response (since the list path represents all platforms).

**Single-platform images:**

For single-platform images, the manifest.json path is queried directly:
```
POST <xray-url>/api/v2/summary/artifact
{ "paths": ["<projectKey>/<repo>/<image>/<tag>/manifest.json"] }
```

This call is **not watch-scoped** — it returns everything Xray has indexed for the artifact across all policies. This gives a complete picture of the image's vulnerability posture.

The response is deduplicated by `issue_id` (the same CVE appearing in multiple platforms counts as one finding) and parsed into two structures:
- `SeverityCounts` — aggregate total, critical, high, medium, low counts
- `[]SummaryIssue` — per-finding detail: `IssueID`, `Severity`, `JFrogSeverity` (JFrog Research severity, may differ from standard), `Fixable` (true if any affected component has a known fix version), `Platforms` (sorted slice of platform labels where the finding was detected)

If the v2 API call fails, a warning is logged and all counts default to zero. No further fallback is attempted.

> **Note:** The v1 summary API (`POST /api/v1/summary/artifact`) hangs indefinitely for Docker images. Always use the v2 endpoint (`/api/v2/summary/artifact`).

---


## 4. Output Formatting

**File:** `internal/check_runner.go` — `outputReport()`

After `generateVulnerabilityReport()` returns, a UI manifest link is constructed (pointing to the image in the JFrog Platform web UI), then the report is formatted.

### JSON output (`--output json`)

`outputJSONReport()` calls `convertToEnhancedReport()` which:
- Flattens all per-platform vulnerabilities into a single list (always empty — Vulnerabilities is nil after Phase 5 removal)
- Counts issue types and malicious findings using `maliciousLookup`
- Produces summary counts from the Phase 4 summary API

The result is a single `EnhancedVulnerabilityReport` struct printed as indented JSON to stdout.

### GitHub Markdown output (`--output github-md`)

`outputMarkdownReport()` produces GitHub-flavored markdown in this order:

1. **Security banner** — a GitHub alert block (rendered before the header for immediate visibility):
   - `[!CAUTION]` (red) if any malicious content found — highest priority
   - `[!CAUTION]` (orange) if critical CVEs found but no malicious content
   - `[!WARNING]` (yellow) if non-critical CVEs found but no malicious or critical content
   - `[!NOTE]` (green) if clean
2. **Header** — image name and a link to the manifest in JFrog Platform UI
3. **Security Summary** — total, critical/high/medium/low counts, malicious count, list of platforms scanned. Counts come from the v2 summary API (Phase 4).
4. **Malicious Findings table** — only appears if malicious issues exist. Lists each issue ID from the malicious watch.
5. **Security Findings table** — a collapsible `<details>` block. Summary line shows total count and fixable count: `Security Findings (293 | 47 fixable) — click to expand`. Filtered by `--min-severity` if specified. Sorted Critical→Low, then XRAY-ID. Columns: XRAY-ID, SEVERITY, JFROG SEVERITY, FIXABLE, PLATFORMS. The PLATFORMS column lists which platform(s) each finding was detected on (e.g. `linux/amd64<br>linux/arm64`). Fixable status, JFrog Research severity, and platform attribution come from the `SummaryIssue` slice returned by Phase 4.

In GitHub Markdown mode, all log output is suppressed (log level set to ERROR) so only the markdown goes to stdout — this makes it safe to pipe directly into a CI pipeline step.

---

## 5. Exit Behavior

If `--fail-on-vuln` is set and `report.TotalIssues > 0`, the command returns a non-zero error. This is what CI pipelines use to gate on vulnerability presence.

---

## Call Stack Summary

```
jf vulnreport check <image> [--repo <repo>] [flags]
└── checkCmd()                             commands/check.go
    └── CheckCommand.Exec()                commands/check.go
        └── RunCheckCommand()              internal/check_runner.go
            ├── ParseImageName(image, repo)  → resolves repoKey / imageName / tag
            ├── getServerDetails()           → JFrog CLI framework (token exchange)
            ├── newXrayService()             → authenticated Xray HTTP client
            ├── newArtifactoryService()      → authenticated Artifactory HTTP client
            └── RunCheckCommandFromConf()  internal/check_runner.go
                └── generateVulnerabilityReport()
                    ├── discoverImageArtifacts()           internal/docker_paths.go
                    │   ├── artSvc.SearchArtifacts()       internal/xray_sdk.go
                    │   │   └── POST /api/search/aql       → Artifactory
                    │   └── expandListManifest()           internal/docker_paths.go
                    │       └── artSvc.FetchArtifactBody() internal/xray_sdk.go
                    │           └── GET list.manifest.json → Artifactory
                    ├── FilterManifestsByPlatform()        internal/docker_paths.go
                    ├── [per platform] xraySvc.GetViolations(malicious-watch)
                    │   └── POST /api/v1/violations        → Xray  (builds maliciousLookup)
                    ├── xraySvc.GetSummaryV2()             internal/xray_sdk.go
                    │   └── POST /api/v2/summary/artifact  → Xray  (severity counts + per-issue detail)
                └── outputReport()
                    ├── outputJSONReport()                 internal/check_runner.go
                    │   └── convertToEnhancedReport()
                    └── outputMarkdownReport()             internal/check_runner.go
                        └── generateSecurityBanner()
```

---

## Key Design Decisions Worth Knowing

**Why a dedicated malicious watch?**
The `--malicious-watch-name` watch is a narrow, purpose-built watch containing only malicious package violations. The Violations API returns a `malicious_package` boolean on each violation, but that field is unreliable in practice. Using a dedicated watch as the ground truth — anything that appears there is definitively malicious — is more robust and avoids false negatives.

**Why does the v2 summary API exist alongside the malicious watch query?**
The v2 summary API (Phase 4) is unscoped — it returns everything Xray has indexed for the image across all policies, not just what one watch captures. This gives a complete picture for compliance reporting. It also returns per-issue `Fixable` status and JFrog Research severity ratings that the Violations API does not provide in the same form. The malicious watch query (Phase 3) remains separate because the v2 summary API does not indicate which issues are malicious.

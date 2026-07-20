# Request Flow: github-md Output

This document describes the complete call flow for a `jf jfrog-vulnreport check` command with `--output=github-md`.

## CLI Invocation

```bash
jf jfrog-vulnreport check <repo/image:tag> \
  --server-id=<server-config-id> \
  --watch-name=<xray-watch-name> \
  --malicious-watch-name=<malicious-xray-watch-name> \
  --output=github-md \
  [--platform=<os/arch>] \
  [--project-key=<xray-project-key>] \
  [--min-severity=<Low|Medium|High|Critical|Malicious>] \
  [--fail-on-vuln] \
  [--show-findings=true|false]
```

## Call Chain Overview

```
jf jfrog-vulnreport check ...
  → main.go:main()
    → plugins.PluginMain(getApp())
      → getApp() → getCommands() → commands.GetCheckCommand()
        → CLI framework parses flags/arguments
          → commands/check.go:checkCmd(c)
            → internal.RunCheckCommand(c)                    ← Entry point
              ├── parseImageName(conf.ImageName)             → (repoKey, imageName, tag)
              ├── getServerDetails(conf.ServerId)           → (*config.ServerDetails)
              │
              └── generateVulnerabilityReport(...)          → (*VulnerabilityReport, maliciousLookup)
                  ├── discoverImageArtifacts(...)           → ([]dockerPath)
                  │   ├── queryArtifactorySearchViaCLI()   → Artifactory search (jf rt search)
                  │   │                                   → JSON artifact list
                  │   └── [if list.manifest.json found]
                  │       └── expandListManifest(...)      → per-platform dockerPath entries
                  │           ├── fetchArtifactoryArtifactBody()  → Artifactory HTTP GET for manifest body
                  │           └── parse JSON into ManifestList
                  │
                  ├── [optional: --platform / --os filtering]
                  │   └── FilterManifestsByPlatform(...)
                  │
                  ├── Phase 1: Malicious watch query (per platform path)
                  │   └── getArtifactSummaryVulnerabilitiesCLI()
                  │       └── queryXrayViolationsViaCLI(..., conf.MaliciousWatchName)
                  │           → POST /api/v1/violations via jf xr curl
                  │           → Extract malicious_package field per violation
                  │           → Build maliciousLookup map[string]bool
                  │
                  ├── Phase 2: Regular watch query (per platform path)
                  │   └── getArtifactSummaryVulnerabilitiesCLI()
                  │       └── queryXrayViolationsViaCLI(..., conf.WatchName)
                  │           → POST /api/v1/violations via jf xr curl
                  │           → Extract vulnerability data per violation
                  │           → Deduplicate into vulnMap
                  │
                  ├── Aggregate platform info into []PlatformVulnerabilityInfo
                  └── Calculate severity counts (Critical, High, Medium, Low)
                  └── Compute orphaned malicious IDs (in malicious watch but not in report watch)
              │
              └── outputReport(report, maliciousLookup, "github-md", manifestUrl, ...)
                  → outputMarkdownReport(...)
                      ├── Print: "# Xray Security Report" + image name
                      ├── Print: "> **View manifest:** [link]" (if manifestUrl provided)
                      ├── [Optional] generateSecurityBanner(...)
                      │   └── Check for malicious content / CVEs using maliciousLookup
                      │       → RED banner ([!CAUTION]) if malicious found
                      │       → YELLOW banner ([!WARNING]) if CVEs present
                      │       → GREEN banner ([!NOTE]) if clean
                      ├── "## Security Summary" section
                      │   ├── Deduplicate vulnerabilities across all platforms
                      │   ├── Count by severity (Critical, High, Medium, Low)
                      │   ├── Count malicious packages from maliciousLookup + orphaned
                      │   └── List scanned platforms (OS/arch pairs)
                      ├── [If malicious findings exist] ":bangbang: Malicious Findings" section
                      │   └── Table of Xray ID → "Malicious" for each finding
                      └── [if --show-findings=true] "## Security Findings" table
                          └── Apply severity filtering via filterVulnerabilitiesBySeverity()
                          └── Per-finding: Xray ID | Type | Severity + emoji icon
```

## Key Architectural Decisions

### Why CLI wrappers instead of SDK?
JWT authentication tokens have audience restrictions that cause 401 errors with direct SDK client calls. All API calls go through `jf xr curl` or `jf rt search` subprocess commands.

### Why Violations API instead of SummaryService?
The Xray SummaryService (`/api/v1/summary/artifact`) hangs indefinitely for Docker images. The Violations API (`/api/v1/violations`) returns the same data reliably.

### Malicious detection optimization
The Violations API already includes `malicious_package` on each violation. We extract this during the initial query and build an in-memory lookup map, eliminating N+1 HTTP requests that were previously needed to check Events API per issue ID.

### Watch-based filtering
Both malicious watch and report watch queries use the same endpoint with different watch names. The malicious watch identifies which issue IDs are malicious; the report watch returns violations for those issues. Comparing them reveals "orphaned" malicious findings (malicious but not flagged as a violation).

## github-md Specific Behavior

| Flag | github-md Effect |
|------|-----------------|
| `--output=github-md` | Sets `Silent=true`, suppresses all log output except ERROR level |
| `--fail-on-vuln` | Returns error if any vulnerabilities found (useful for CI) |
| `--show-findings=false` | Omits the detailed Security Findings table from markdown output |
| `--min-severity=X` | Filters findings table entries; summary counts still show all severities |

## Output Structure

The github-md output consists of these sections in order:

1. **Header**: `# Xray Security Report` + image name link to manifest in JFrog Platform UI
2. **[Optional] Security Banner**: RED / YELLOW / GREEN alert banner based on findings
3. **Security Summary**: Total findings, counts by severity, malicious count, platforms scanned
4. **[If applicable] Malicious Findings**: Table of malicious package IDs (separate section)
5. **[If show-findings=true] Security Findings**: Detailed table with type and severity for each finding

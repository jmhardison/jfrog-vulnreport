# Release Notes

## v0.1.7

- Added `--project-key` flag for Xray violation queries scoped to a JFrog project
- Added `--malicious-watch-name` flag as the authoritative source for malicious package detection (replaces unreliable Violations API `malicious_package` field)
- Migrated all Xray and Artifactory API calls to direct SDK HTTP client — removes dependency on `jf` subprocess calls
- Added dual-path discovery for single-platform and multi-platform (manifest list) Docker images
- Switched vulnerability summary to Xray v2 Summary API (`/api/v2/summary/artifact`) — includes severity counts, JFrog Research severity, fixable status, and per-finding platform attribution
- Fixed `github-md` log leakage — log output is fully suppressed in markdown mode
- Added `--malicious-watch-name` required guard
- Deterministic JSON output (sorted `maliciousIssues` array)
- `Malicious` severity supported in `--min-severity` filter and sort order

## v0.1.4

- Added `--no-findings` flag to suppress the Security Findings detail table while keeping summary counts and malicious findings visible
- Added No Image Found state with grey badge when image is not present in Artifactory

## v0.1.3

- Initial public release
- `check` command with `json` and `github-md` output formats
- Four-tier GitHub MD alert banner (malicious / critical / findings / clean)
- Multi-platform image support via `list.manifest.json` discovery
- `--platform` filter for OS and architecture
- `--fail-on-vuln` exit code support
- `--min-severity` filter

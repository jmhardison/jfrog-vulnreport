# Release Notes

## v0.1.10

- feat: add `table` output format (Unicode box-drawing tables) as the new default — `--output json` now required to get JSON output when not specified
- feat: replace `--debug-paths` flag with `--debug` — enables DEBUG-level logging for troubleshooting artifact discovery
- feat: default log level changed from INFO to WARN for `table` and `json` output — operational progress messages no longer appear unless `--debug` is set
- feat: ANSI severity colors in `table` output (Critical/Malicious=red, High=yellow, Medium=cyan) — omitted automatically when stdout is not a TTY
- feat: add `--save-output` flag — comma-separated list of `json` and/or `github-md`; writes `vulnreport.json` / `vulnreport.md` to the current working directory without re-querying JFrog APIs; console shows only "Saved: …"
- feat: add `ck` alias for the `check` command — `jf vulnreport ck` dispatches the same action as `jf vulnreport check`
- feat: JSON output now includes `pluginName` and `pluginVersion` fields at the top level of every report — enables downstream tooling to track which plugin version generated the file

## v0.1.9

- fix: update from badgeio to baked png images.


## v0.1.8

- feat(init): initial design and implementation. (#8)
- Initial commit


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

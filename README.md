# vulnreport

JFrog CLI plugin that reads **existing Xray scan results** for a Docker image and outputs a consolidated vulnerability report.

**Not a standalone scanner.** It queries artifacts already indexed by Xray and enriches them with security findings from cached scans. Use the native JFrog CLI Xray commands or IDE integrations to scan first, then use this plugin for reporting.

## Install

### From JFrog Plugin Registry

```bash
jf plugin install vulnreport
```

### From Source

```bash
git clone https://github.com/jmhardison/jfrog-vulnreport.git
cd jfrog-vulnreport
go build -o vulnreport .
cp vulnreport ~/.jfrog/plugins/vulnreport/bin/
```

### Uninstall

```bash
jf plugin uninstall vulnreport
```

## Prerequisites

- JFrog CLI configured with a server ID (`jf c add`)
- An Xray watch configured for malicious package detection — pass its name via `--malicious-watch-name`
- Docker images already indexed by Xray (scan before reporting)

## Command

### `check`

Reads existing vulnerability scan results for a Docker image from Xray and outputs a consolidated report.

**Usage**

```bash
jf vulnreport check <repo/image:tag> [flags]
```

**Arguments**

| Argument | Description |
|---|---|
| `repo/image:tag` | Full image reference including the Artifactory repository (e.g., `docker-local/team/myapp:1.2.3`) |

**Flags**

| Flag | Required | Default | Description |
|---|---|---|---|
| `--malicious-watch-name` | Yes | — | Xray watch name used as the authoritative source for malicious package detection |
| `--server-id` | No | default server | JFrog CLI server configuration ID |
| `--output` | No | `json` | Output format: `json` or `github-md` |
| `--min-severity` | No | — | Minimum severity to include in findings: `Low`, `Medium`, `High`, `Critical`, `Malicious` |
| `--platform` | No | all platforms | Filter by platform — `os/arch` (e.g., `linux/amd64`) or OS only (e.g., `linux`) |
| `--fail-on-vuln` | No | `false` | Exit non-zero if any vulnerabilities are found |
| `--no-findings` | No | `false` | Suppress the Security Findings detail table (summary counts and malicious findings still shown) |
| `--project-key` | No | `default` | Xray project key for violation queries — only needed when the watch is scoped to a JFrog project |
| `--docker-registry-url` | No | derived from server | Override the Docker registry base URL |
| `--debug-paths` | No | `false` | Log artifact discovery paths for troubleshooting |

**Examples**

```bash
# Basic report — JSON output
jf vulnreport check docker-local/team/myapp:1.2.3 \
  --malicious-watch-name org-malicious-watch \
  --server-id my-server

# GitHub Actions CI — markdown with banner, hide detail table, fail on findings
jf vulnreport check docker-local/team/myapp:1.2.3 \
  --malicious-watch-name org-malicious-watch \
  --output github-md \
  --min-severity High \
  --no-findings \
  --fail-on-vuln

# Filter to a single platform
jf vulnreport check docker-local/team/myapp:1.2.3 \
  --malicious-watch-name org-malicious-watch \
  --platform linux/amd64
```

## Output Formats

### `json` (default)

Structured JSON including image metadata, severity counts, platform list, malicious issue IDs, and a full findings array. Suitable for downstream tooling and audit pipelines.

### `github-md`

GitHub-flavored Markdown designed for CI pipeline output. Emits:

- A colored alert banner indicating the highest severity state:
  - `[!CAUTION]` **red** — malicious packages detected
  - `[!CAUTION]` **orange** — critical CVEs, no malicious
  - `[!WARNING]` **yellow** — non-critical CVEs
  - `[!NOTE]` **green** — clean image

- A Security Summary section with severity counts and fixable counts
- A collapsible Security Findings table (suppressed with `--no-findings`)
- A Malicious Findings table when malicious packages are present

Log output is suppressed in `github-md` mode so only the markdown reaches stdout.

## Release Notes

See [RELEASE.md](RELEASE.md).

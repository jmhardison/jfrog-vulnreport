# vulnreport

JFrog CLI plugin that reads **existing Xray scan results** for a Docker image and outputs a consolidated vulnerability report.

## Install

Install from source:

```bash
go build -o vulnreport .
jf plugin install vulnreport
```

Uninstall:

```bash
jf plugin uninstall vulnreport
```

## Command

### `check`

Checks vulnerabilities for a Docker image already scanned by Xray.

**Usage**

```bash
jf vulnreport check <repo/image:tag> [flags]
```

**Flags**

- `--server-id` JFrog CLI server configuration ID
- `--platform` Platform filter — `os/arch` (e.g., `linux/amd64`) or OS only (e.g., `linux`)
- `--fail-on-vuln` Exit non-zero if vulnerabilities are found
- `--output` Output format: `json` (default) or `github-md`
- `--min-severity` Minimum severity to display (`Low`, `Medium`, `High`, `Critical`, `Malicious`)
- `--no-findings` Suppress the Security Findings table in output (summary counts and malicious findings are still shown)
- `--debug-paths` Enable Xray path discovery logs
- `--docker-registry-url` Override Docker registry base URL

**Examples**

```bash
jf vulnreport check docker-local/team/myapp:1.2.3 --server-id my-server
jf vulnreport check docker-local/team/myapp:1.2.3 --output github-md --min-severity High
```

## Release Notes

See [RELEASE.md](RELEASE.md).

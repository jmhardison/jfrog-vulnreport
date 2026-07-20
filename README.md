# jfrog-vulnreport

JFrog CLI plugin that reads **existing Xray scan results** for a Docker image and outputs a consolidated vulnerability report.
The retrieval flow is **Violations API first** (`api/v1/violations` via JFrog client-go), with a Summary API fallback for compatibility.

## Install

Install from source:

```bash
go build -o jfrog-vulnreport .
jf plugin install jfrog-vulnreport
```

Uninstall:

```bash
jf plugin uninstall jfrog-vulnreport
```

## Command

### `check`

Checks vulnerabilities for a Docker image already scanned by Xray.
By default, it queries Xray violations for matching artifact paths, then falls back to summary/discovery lookup when needed.

**Usage**

```bash
jf jfrog-vulnreport check <repo/image:tag> [flags]
```

**Flags**

- `--server-id` JFrog CLI server configuration ID
- `--platform` Platform architecture filter (`amd64`, `arm64`, ...)
- `--os` Operating system filter (`linux`, `windows`, ...)
- `--fail-on-vuln` Exit non-zero if vulnerabilities are found
- `--output` Output format: `json` (default) or `github-md`
- `--min-severity` Minimum severity to display (`Low`, `Medium`, `High`, `Critical`, `Malicious`)
- `--show-findings` Show findings table (default: `true`)
- `--debug-paths` Enable Xray path discovery logs
- `--docker-registry-url` Override Docker registry base URL

**Examples**

```bash
jf jfrog-vulnreport check docker-local/team/myapp:1.2.3 --server-id my-server
jf jfrog-vulnreport check docker-local/team/myapp:1.2.3 --output github-md --min-severity High
```

## Release Notes

See [RELEASE.md](RELEASE.md).

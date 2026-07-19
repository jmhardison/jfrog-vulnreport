# How to Test

## Prerequisites
- JFrog CLI installed (`jf`) — configured with a server via `jf config add`
- Go 1.24+ on PATH

## Quick Build + Install Cycle

```bash
# 1. Build the binary
go build -o jfrog-vulnreport .

# 2. Test locally (no install needed)
jf jfrog-vulnreport check docker-local/myimage:latest --server-id=my-server | jq .

# 3. Install as a JFrog CLI plugin (optional, for persistent use)
go build -o jfrog-vulnreport . && jf plugin install jfrog-vulnreport
```

## Output Format Options

```bash
# Default JSON output (EnhancedVulnerabilityReport with per-platform findings)
jf jfrog-vulnreport check <image:tag> --server-id=<name>

# GitHub Markdown for CI/CD pipelines (silent, with security banner)
jf jfrog-vulnreport check <image:tag> --server-id=<name> \
    --output=github-md --min-severity High
```

## Key Flags

| Flag | Description | Default | Example |
|------|-------------|---------|---------|
| `--server-id` | JFrog CLI server configuration ID | (from current config) | `my-server` |
| `--platform` | Filter by platform (`os/arch`) | all platforms | `linux/amd64`, `windows/amd64` |
| `--project-key` | Xray project key for violation queries | `default` | `my-project` |
| `--output` | Output format: `json` or `github-md` | `json` | `github-md` |
| `--min-severity` | Minimum severity to display: `Low`, `Medium`, `High`, `Critical`, `Malicious` | all severities | `High` |
| `--show-findings` | Include detailed findings table (markdown only) | false | true |
| `--fail-on-vuln` | Exit non-zero if any vulnerabilities found | false | true |

## Uninstall

```bash
jf plugin uninstall jfrog-vulnreport
# Or manually remove the install directory
rm -rf ~/.jfrog/plugins/jfrog-vulnreport/
```

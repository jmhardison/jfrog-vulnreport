# How to Test

## Prerequisites
- JFrog CLI installed (`jf`)
- Go 1.17+ on PATH (or Docker with a Go image)

## Quick Build + Install Cycle

```bash
# 1. Build
go build -o jfrog-vulnreport .

# 2. Place binary in JFrog CLI plugin directory
mkdir -p ~/.jfrog/plugins/jfrog-vulnreport/bin
cp jfrog-vulnreport ~/.jfrog/plugins/jfrog-vulnreport/bin/

# 3. Test the install
jf jfrog-vulnreport --help

# 4. Test a check command (against your own Xray instance)
jf jfrog-vulnreport check <image:tag> --server-id=<name> \
    --platform=linux \
    --output=json | jq .
```

## Install Path for Windows/macOS with `go install`

```bash
# Build + move to $GOPATH/bin (if JFrog CLI is configured to use plugins from there)
mkdir -p ~/.jfrog/plugins/jfrog-vulnreport/bin
cp jfrog-vulnreport ~/.jfrog/plugins/jfrog-vulnreport/bin/
```

## Output Format Options

```bash
# Default JSON output
jf jfrog-vulnreport check <image:tag> --server-id=<name>

# GitHub Markdown for CI/CD with security badges
jf jfrog-vulnreport check <image:tag> --server-id=<name> \
    --output=github-md --min-severity High
```

## Key Flags
- `--help`: Display help information
- `--server-id`: JFrog CLI server configuration ID (default from current config)
- `--platform`: Filter by platform (`linux`, `windows`)
- `--os`: Filter by operating system
- `--output`: Output format, `json` or `github-md`
- `--min-severity`: Minimum severity to display

## Uninstall
```bash
jf plugin uninstall jfrog-vulnreport
# Or manually remove the install directory
rm -rf ~/.jfrog/plugins/jfrog-vulnreport/
```

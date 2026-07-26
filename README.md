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

### `check` (alias: `ck`)

Reads existing vulnerability scan results for a Docker image from Xray and outputs a consolidated report.

**Usage**

```bash
jf vulnreport check <image:tag> [flags]
jf vulnreport check <repo/image:tag> [flags]
jf vulnreport ck <image:tag> [flags]
```

**Arguments**

| Argument | Description |
|---|---|
| `image:tag` | Docker image name and tag. The Artifactory repository can be included as a prefix (`repo/image:tag`) or omitted — when omitted, `--repo` is used. Nested image paths are supported (e.g., `team/myapp:1.2.3`). |

**Flags**

| Flag | Required | Default | Description |
|---|---|---|---|
| `--malicious-watch-name` | Yes | — | Xray watch name used as the authoritative source for malicious package detection |
| `--repo` | No | `docker-local` | Artifactory repository key containing the Docker image. Used when the image argument does not include a repository prefix. |
| `--server-id` | No | default server | JFrog CLI server configuration ID |
| `--output` | No | `table` | Output format: `table`, `json`, or `github-md` |
| `--min-severity` | No | — | Minimum severity to include in the Security Findings table: `Low`, `Medium`, `High`, `Critical`, `Malicious`. The Security Summary always shows all severity counts regardless of this filter. |
| `--platform` | No | all platforms | Filter by platform — `os/arch` (e.g., `linux/amd64`) or OS only (e.g., `linux`) |
| `--fail-on-vuln` | No | `false` | Exit non-zero if any vulnerabilities are found |
| `--no-findings` | No | `false` | Suppress the Security Findings detail table (summary counts and malicious findings still shown) |
| `--project-key` | No | `default` | Xray project key for violation queries — only needed when the watch is scoped to a JFrog project |
| `--docker-registry-url` | No | derived from server | Override the Docker registry base URL |
| `--debug` | No | `false` | Enable debug-level logging for troubleshooting |

**Log verbosity**

| Condition | Log level | Effect |
|---|---|---|
| `--debug` | DEBUG | Full SDK trace, artifact discovery details, API call details |
| default (`table` or `json`) | WARN | Warnings and errors only — keeps stdout clean for piping |
| `--output github-md` | ERROR | All non-error log output suppressed — only markdown reaches stdout |

**Examples**

```bash
# Basic report — image:tag only, repo defaults to docker-local
jf vulnreport check team/myapp:1.2.3 \
  --malicious-watch-name org-malicious-watch \
  --server-id my-server

# Explicit repo when your registry key differs from docker-local
jf vulnreport check team/myapp:1.2.3 \
  --repo docker-prod-local \
  --malicious-watch-name org-malicious-watch \
  --server-id my-server

# Repo included in the image argument (backward-compatible form)
jf vulnreport check docker-local/team/myapp:1.2.3 \
  --malicious-watch-name org-malicious-watch \
  --server-id my-server

# GitHub Actions CI — markdown with banner, hide detail table, fail on findings
jf vulnreport check team/myapp:1.2.3 \
  --malicious-watch-name org-malicious-watch \
  --output github-md \
  --min-severity High \
  --no-findings \
  --fail-on-vuln

# Filter to a single platform
jf vulnreport check team/myapp:1.2.3 \
  --malicious-watch-name org-malicious-watch \
  --platform linux/amd64
```

## Output Formats

### `table` (default)

CLI-friendly Unicode box-drawing tables rendered to stdout. Sections:

- Header with image name and link to the JFrog Platform manifest view
- Status line indicating the highest-severity state (malicious / critical / CVEs / clean)
- **Security Summary** table — total, critical, high, medium, low, fixable, malicious, platform count
- **Malicious Findings** table — listed when malicious packages are detected
- **Security Findings** table — one row per issue with XRAY-ID, severity, JFrog Research severity, fixable, and platforms. Filtered by `--min-severity`. Suppressed with `--no-findings`.
- Footer with version and timestamp

ANSI colors are applied automatically when stdout is a TTY (red for Critical/Malicious, yellow for High, cyan for Medium). Colors are omitted when piping to a file or another command.

### `json`

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

## Example Output

The following show `--output github-md` output for each possible report state. Image names, XRAY IDs, and server URLs use placeholder values. Findings tables are truncated for brevity.

---

### Malicious Content Detected

Emitted when the `--malicious-watch-name` watch returns violations for the image. This banner takes highest priority over all other states.

<details>
<summary>View example</summary>

![Malicious](https://raw.githubusercontent.com/jmhardison/jfrog-vulnreport/main/images/badge-malicious.png)
---

> [!CAUTION]
> ## :rotating_light: MALICIOUS EXPLOIT PRESENT :rotating_light:
> **IMMEDIATE ACTION REQUIRED** - Malicious content detected in this image. Remediate or seek guidance.
> Policies can prevent the download and execution of this image, resulting in potential deploy issues such as `imagePullBackoff`.
> Do `not` promote until confirmed, and stop use of image if not a false positive.


---

# Xray Security Report

## docker-local/myapp:1.2.3

> **View manifest:** [docker-local/myapp:1.2.3](https://example.jfrog.io/ui/repos/tree/Xray/docker-local/myapp/1.2.3/manifest.json)


## Security Summary
- **Total Findings:** 85
- **Critical:** 12 | **High:** 45 | **Medium:** 25 | **Low:** 3
- **Malicious:** 2
- **Platforms Scanned:** 1
- **Platforms:** linux/amd64


---

## :bangbang: Malicious Findings (2)
| Xray ID | Severity |
|---------|----------|
| XRAY-200001 | :skull: Malicious :skull: |
| XRAY-200002 | :skull: Malicious :skull: |

---


---

<details>
<summary>Security Findings (85 | 18 fixable) — click to expand</summary>

| XRAY-ID | SEVERITY | JFROG SEVERITY | FIXABLE | PLATFORMS |
|---------|----------|----------------|---------|-----------|
| XRAY-100001 | :red_square: Critical | :red_square: Critical | Yes | linux/amd64 |
| XRAY-100002 | :red_square: Critical | :arrow_up_small: :red_square: Critical | No | linux/amd64 |
| XRAY-100003 | :orange_square: High | :orange_square: High | Yes | linux/amd64 |
| XRAY-100004 | :orange_square: High | :arrow_down_small: :yellow_square: Medium | No | linux/amd64 |
| XRAY-100005 | :yellow_square: Medium | :yellow_square: Medium | No | linux/amd64 |

</details>


---

> Xray scans trigger at upload time, but can be matched to new vulnerabilities over time without rescans.
> These are findings as of 2026-01-15T10:30:00-05:00.

> Generated by vulnreport v0.1.9

</details>

---

### Critical CVEs Present

Emitted when critical severity findings exist and no malicious content is detected. Also shown for images with nested path names (e.g. `team/api-server`).

<details>
<summary>View example</summary>

![Critical CVEs](https://raw.githubusercontent.com/jmhardison/jfrog-vulnreport/main/images/badge-critical-cve.png)
---

> [!CAUTION]
> ## :red_circle: CRITICAL CVE'S PRESENT
> Critical severity vulnerabilities found - review and remediation required.
> Fixable critical issues should be resolved before promotion.


---

# Xray Security Report

## docker-local/platform/api-server:3.1.0

> **View manifest:** [docker-local/platform/api-server:3.1.0](https://example.jfrog.io/ui/repos/tree/Xray/docker-local/platform/api-server/3.1.0/manifest.json)


## Security Summary
- **Total Findings:** 61
- **Critical:** 3 | **High:** 27 | **Medium:** 28 | **Low:** 3
- **Malicious:** 0
- **Platforms Scanned:** 1
- **Platforms:** linux/amd64


---

<details>
<summary>Security Findings (61 | 12 fixable) — click to expand</summary>

| XRAY-ID | SEVERITY | JFROG SEVERITY | FIXABLE | PLATFORMS |
|---------|----------|----------------|---------|-----------|
| XRAY-100010 | :red_square: Critical | :red_square: Critical | Yes | linux/amd64 |
| XRAY-100011 | :red_square: Critical | :red_square: Critical | No | linux/amd64 |
| XRAY-100012 | :red_square: Critical | :arrow_up_small: :red_square: Critical | Yes | linux/amd64 |
| XRAY-100013 | :orange_square: High | :orange_square: High | Yes | linux/amd64 |
| XRAY-100014 | :orange_square: High | :orange_square: High | No | linux/amd64 |

</details>


---

> Xray scans trigger at upload time, but can be matched to new vulnerabilities over time without rescans.
> These are findings as of 2026-01-15T10:30:00-05:00.

> Generated by vulnreport v0.1.9

</details>

---

### CVEs Present

Emitted when vulnerabilities are found, none are critical, and no malicious content is detected. Multi-platform images list each platform in the PLATFORMS column.

<details>
<summary>View example</summary>

![CVEs Present](https://raw.githubusercontent.com/jmhardison/jfrog-vulnreport/main/images/badge-cves-present.png)
---

> [!WARNING]
> ## :warning: CVE's PRESENT
> Security vulnerabilities found - review and remediate as needed
> Promotion won't be blocked, however fixable issues should be resolved before promotion when possible.


---

# Xray Security Report

## docker-local/web-service:latest

> **View manifest:** [docker-local/web-service:latest](https://example.jfrog.io/ui/repos/tree/Xray/docker-local/web-service/latest/list.manifest.json)


## Security Summary
- **Total Findings:** 55
- **Critical:** 0 | **High:** 34 | **Medium:** 20 | **Low:** 1
- **Malicious:** 0
- **Platforms Scanned:** 2
- **Platforms:** linux/amd64, linux/arm64


---

<details>
<summary>Security Findings (55 | 10 fixable) — click to expand</summary>

| XRAY-ID | SEVERITY | JFROG SEVERITY | FIXABLE | PLATFORMS |
|---------|----------|----------------|---------|-----------|
| XRAY-100020 | :orange_square: High | :orange_square: High | Yes | linux/amd64<br>linux/arm64 |
| XRAY-100021 | :orange_square: High | :arrow_up_small: :red_square: Critical | No | linux/amd64 |
| XRAY-100022 | :orange_square: High | :orange_square: High | Yes | linux/arm64 |
| XRAY-100023 | :yellow_square: Medium | :yellow_square: Medium | No | linux/amd64<br>linux/arm64 |
| XRAY-100024 | :brown_square: Low | :brown_square: Low | No | linux/amd64<br>linux/arm64 |

</details>


---

> Xray scans trigger at upload time, but can be matched to new vulnerabilities over time without rescans.
> These are findings as of 2026-01-15T10:30:00-05:00.

> Generated by vulnreport v0.1.9

</details>

---

### No Findings

Emitted when Xray reports no vulnerabilities for the image.

<details>
<summary>View example</summary>

![No Findings](https://raw.githubusercontent.com/jmhardison/jfrog-vulnreport/main/images/badge-no-findings.png)
---

> [!NOTE]
> ## :white_check_mark: NO FINDINGS
> No security issues found - image appears clean


---

# Xray Security Report

## docker-local/base-image:20260115

> **View manifest:** [docker-local/base-image:20260115](https://example.jfrog.io/ui/repos/tree/Xray/docker-local/base-image/20260115/manifest.json)


## Security Summary
- **Total Findings:** 0
- **Critical:** 0 | **High:** 0 | **Medium:** 0 | **Low:** 0
- **Malicious:** 0
- **Platforms Scanned:** 1
- **Platforms:** linux/amd64

---

> Xray scans trigger at upload time, but can be matched to new vulnerabilities over time without rescans.
> These are findings as of 2026-01-15T10:30:00-05:00.

> Generated by vulnreport v0.1.9

</details>

---

### Image Not Found

Emitted when AQL finds no manifest files for the given image and tag — typically a misspelled name, an unpublished image, or an image not yet indexed by Xray.

<details>
<summary>View example</summary>

![No Image Found](https://raw.githubusercontent.com/jmhardison/jfrog-vulnreport/main/images/badge-no-image-found.png)
---

# Xray Security Report

## docker-local/missing-image:notag

No Image Found - Check the image name/tag, or that publishing is complete.

> Generated by vulnreport v0.1.9

</details>

---

## Release Notes

See [RELEASE.md](RELEASE.md).

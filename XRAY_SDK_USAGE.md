# Correct JFrog Xray SDK Usage for Fetching Existing Scan Results

## Problem with Original Approach

The original implementation was using:
```go
summaryService := services.NewSummaryService(xrManager.Client())
summaryService.GetArtifactSummary(params)
```

This approach had several issues:

1. **Wrong Service Purpose**: `SummaryService.GetArtifactSummary()` is primarily for getting basic artifact metadata, not comprehensive vulnerability reports
2. **Incorrect Path Format**: Docker image references need specific formatting for Xray APIs
3. **Missing Alternative Services**: Better services exist for fetching scan results

## Corrected Approaches

### 1. ReportService (Primary Method)

**Purpose**: Fetch comprehensive vulnerability reports from existing scans

```go
reportService := services.NewReportService(xrManager.Client())
reportService.XrayDetails = xrManager.Config().GetServiceDetails()

reportParams := services.VulnerabilitiesReportRequestParams{
    Filters: services.VulnerabilitiesFilter{
        ArtifactPath: artifactPath,
    },
}

reportResp, err := reportService.Vulnerabilities(reportParams)
```

**When to Use**: 
- When you need detailed vulnerability reports
- For artifacts that have been scanned and indexed
- When you need comprehensive CVE information

### 2. ArtifactService (Status Check)

**Purpose**: Check if an artifact has been scanned and get scan status

```go
artifactService := services.NewArtifactService(xrManager.Client())
artifactService.XrayDetails = xrManager.Config().GetServiceDetails()

statusResp, err := artifactService.GetStatus(repo, path)
```

**When to Use**:
- To verify if an artifact has been scanned
- To check scan completion status
- Before attempting to fetch vulnerability data

### 3. SummaryService (Fallback)

**Purpose**: Get basic artifact information and high-level issue counts

```go
summaryService := services.NewSummaryService(xrManager.Client())
summaryService.XrayDetails = xrManager.Config().GetServiceDetails()

params := services.ArtifactSummaryParams{
    Paths: []string{artifactPath},
}

summary, err := summaryService.GetArtifactSummary(params)
```

**When to Use**:
- As a fallback when other services fail
- For basic artifact metadata
- When you only need issue counts, not detailed vulnerability information

## Docker Image Path Formats

The key insight is that Xray stores Docker images in various path formats. The corrected implementation tries multiple formats:

### Standard Formats
1. `docker-local/myimage:1.0` (standard Docker registry format)
2. `docker-local/myimage/1.0` (flat structure)
3. `docker-local:myimage/1.0` (colon-separated)

### Alternative Formats
4. `docker-local/library/myimage:1.0` (with library namespace)
5. `docker-local/myimage-1.0` (hyphen-separated)
6. `docker-local/myimage_1.0` (underscore-separated)
7. `myimage:1.0` (without repo prefix)

### Special Cases
8. Latest tag fallbacks
9. URL-encoded formats for special characters

## Differences Between Services

| Service | Primary Use Case | Returns | Best For |
|---------|------------------|---------|----------|
| **ReportService** | Comprehensive vulnerability reports | Detailed vulnerability data with CVEs, CVSS scores, remediation | Production vulnerability analysis |
| **ArtifactService** | Artifact scan status | Scan completion status, timestamps | Checking if artifact is ready for analysis |
| **SummaryService** | Basic artifact metadata | High-level issue counts, basic info | Quick overview, fallback scenario |
| **ScanService** | Initiate new scans | Scan ID for tracking | When you need to trigger new scans |

## Key Parameter Differences

### For ReportService:
```go
services.VulnerabilitiesReportRequestParams{
    Filters: services.VulnerabilitiesFilter{
        ArtifactPath: "docker-local/myimage:1.0",
        // Can also include severity filters, date ranges, etc.
    },
}
```

### For ArtifactService:
```go
// Requires separate repo and path parameters
artifactService.GetStatus("docker-local", "myimage:1.0")
```

### For SummaryService:
```go
services.ArtifactSummaryParams{
    Paths: []string{"docker-local/myimage:1.0"},
    Checksums: []string{"sha256:abc123..."}, // optional
}
```

## Common Issues and Solutions

### Issue: "Artifact doesn't exist or not indexed/cached in Xray"

**Causes**:
1. Incorrect path format
2. Artifact not yet scanned/indexed
3. Repository not configured for Xray scanning

**Solutions**:
1. Try multiple path formats (implemented in corrected code)
2. Check artifact status with ArtifactService first
3. Verify Xray indexing configuration
4. Use discovery methods to find actual artifact paths in Xray

### Issue: Empty results despite known vulnerabilities

**Causes**:
1. Using wrong service for the use case
2. Timing issues (scan not complete)
3. Permissions/configuration issues

**Solutions**:
1. Use ReportService for comprehensive results
2. Check scan status before fetching results
3. Verify Xray watches and policies are configured

## Implementation Pattern

The corrected implementation follows this pattern:

```go
func getVulnerabilityReport(xrManager *xray.XrayServicesManager, artifactPath, sha256 string) ([]services.Vulnerability, error) {
    // 1. Try ReportService for comprehensive results
    // 2. Try ArtifactService to check status  
    // 3. Fall back to SummaryService
    // 4. Try multiple path formats for each approach
    // 5. Provide discovery methods if all fail
}
```

This multi-layered approach ensures maximum compatibility with different Xray configurations and deployment scenarios.
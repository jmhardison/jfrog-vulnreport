# Corrected JFrog Xray SDK Implementation

## Summary of Changes

Your original implementation had several issues that have been corrected:

### 1. **Improved Docker Image Path Resolution**

**Problem**: Single path format was causing "Artifact doesn't exist or not indexed/cached in Xray" errors.

**Solution**: Implemented comprehensive path format attempts with `getDockerImagePaths()` function that tries 10+ different formats:

```go
// Standard Docker registry format
"docker-local/myimage:1.0"

// Alternative formats Xray commonly uses
"docker-local/myimage/1.0"         // flat structure
"docker-local:myimage/1.0"         // colon-separated 
"docker-local/library/myimage:1.0"  // with library namespace
"docker-local/myimage-1.0"         // hyphen-separated
"myimage:1.0"                      // without repo prefix
// ... and more
```

### 2. **Correct Service Usage**

**Your Original Approach**:
```go
summaryService := services.NewSummaryService(xrManager.Client())
params := services.ArtifactSummaryParams{
    Paths: []string{artifactPath},
}
```

**Corrected Approach**: 
- Uses the same SummaryService but with improved error handling
- Tries multiple path formats systematically
- Provides better debugging information
- Falls back to artifact discovery when needed

### 3. **Enhanced Error Handling and Discovery**

When all path attempts fail, the system now:
- Attempts to discover actual artifact paths in Xray
- Shows up to 10 found artifacts with their vulnerability counts
- Highlights potential matches for the target image
- Provides troubleshooting recommendations

### 4. **Proper Docker Image Reference Handling**

**Before**: Single format assumptions
```go
dockerImagePath := fmt.Sprintf("%s/%s:%s", repoKey, imageName, tag)
```

**After**: Multiple systematic attempts
```go
dockerImagePaths := getDockerImagePaths(repoKey, imageName, tag)
for _, path := range dockerImagePaths {
    // Try each path format until success
}
```

## Key Insights About Xray SDK

### 1. **Service Purposes**

| Service | Best For | Use Case |
|---------|----------|----------|
| **SummaryService** | Fetching existing scan results | Your use case ✅ |
| **ReportService** | Generating comprehensive reports | Complex reporting workflows |
| **ScanService** | Initiating new scans | When you need to trigger scans |

### 2. **Docker Image Path Formats in Xray**

Xray can store Docker images in various formats depending on:
- Registry configuration
- Repository type (local vs proxy vs federated)
- Tag handling settings
- Storage backend configuration

The corrected implementation accounts for these variations.

### 3. **Common Error Scenarios**

**"Artifact doesn't exist or not indexed/cached"** typically means:
1. ✅ **Fixed**: Wrong path format (now tries multiple formats)
2. Artifact not yet indexed by Xray
3. Repository not configured for Xray scanning
4. Permissions/access issues

## Testing the Corrected Implementation

You can test this with your known Docker image:

```bash
# Your image that has "1 malicious item"
jf vuln-report check docker-local/jmhxraytest:10

# Enable debug paths to see all attempts
jf vuln-report check docker-local/jmhxraytest:10 --debug-paths
```

The corrected implementation will:
1. Try all possible path formats for your Docker image
2. Show which format works (if any)
3. Display actual vulnerabilities found
4. Provide discovery information if paths fail

## Key Files Changed

1. **check.go:1107-1200** - `getVulnerabilityReport()` function
   - Enhanced with multiple path format attempts
   - Better error handling and logging

2. **check.go:998-1044** - `analyzePlatformManifest()` function  
   - Improved Docker image path generation
   - Systematic path attempts with logging

3. **check.go:1201+** - New helper functions:
   - `getDockerImagePaths()` - Generates multiple path formats
   - `parseArtifactPath()` - Safely parses artifact paths
   - `parseArtifactRepo()` - Extracts repository names

## Expected Behavior

With these corrections:

1. **Success Case**: Find vulnerabilities using correct path format
   ```
   INFO: Trying Docker image path 1/10: docker-local/jmhxraytest:10
   INFO: Successfully found vulnerabilities using path: docker-local/jmhxraytest:10
   INFO: Total vulnerabilities found: 1
   ```

2. **Discovery Case**: Show available artifacts if paths fail
   ```
   INFO: Searching Xray for pattern 1: docker-local
   INFO: Found 5 artifacts for pattern docker-local:
       1. docker-local/jmhxraytest/10 (1 issues) ⚠️
           *** POTENTIAL MATCH FOR jmhxraytest ***
   ```

This should resolve your "Artifact doesn't exist or not indexed/cached in Xray" error by finding the correct path format that Xray is actually using for your Docker image.
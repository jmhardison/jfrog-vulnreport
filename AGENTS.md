# AGENTS.md

## Project Scope
JFrog CLI plugin that queries existing Xray scan results for Docker images. Not a standalone tool — registers as `jf jfrog-vulnreport check`.

## Commands
```bash
go build -o jfrog-vulnreport .    # Build binary
go test ./...                      # Run tests (none exist yet)
jf plugin install jfrog-vulnreport # Install as JFrog CLI plugin
```

## Architecture Notes
- **Single command**: `check` — no subcommands planned
- **Output formats**: `json` (default, enhanced report structure), `github-md` (markdown with security banner for GitHub)
- **Xray integration**: Uses SummaryService API; includes fallback discovery if direct paths fail
- **Malicious package detection**: In-memory cache keyed by issue ID via Events API

## Gotchas
1. **No tests exist** — registry requires `go vet ./... && go test ./...` to pass; add tests before publishing publicly
2. **Registry path resolution** is brittle — only tries Docker Hub tag formats (e.g., `vulns/findings/{id}`); may need to support JFrog-specific patterns (`latest`, version numbers) for full compatibility

## Code Organization
- `main.go` — entry point, registers plugin with framework `github.com/jfrog/jfrog-cli-core/v2/plugins`; version (`v0.1.2`) declared in `app.Version`
- `commands/check.go` — single file: CLI flags + arg parsing; each new command gets its own file here
- `internal/` — business logic (models, check runner, helpers)
- Single package boundary — no splitting needed for now

## Publishing to Registry
1. Add a YAML descriptor (e.g., `jfrog-vulnreport.yml`) to [jfrog-cli-plugins-reg](https://github.com/jfrog/jfrog-cli-plugins-reg/tree/master/plugins), include required fields (`pluginName`, `version` with `v` prefix, `repository`, `maintainers`)
2. Accept the developer terms file from that registry before PR is merged
3. Plugin name must be lowercase + numbers/dashes, max 30 chars; README.md needed at repo root structured like [the template](https://github.com/jfrog/jfrog-cli-plugin-template)

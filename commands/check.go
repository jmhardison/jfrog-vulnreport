package commands

import (
	"fmt"

	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	helperinternal "github.com/jmhardison/jfrog-vulnreport/internal"
)

// CheckCommand holds all parameters and dependencies for a vulnerability check invocation.
// Mirrors the build-deps-info pattern: a struct with fluent setters for dependency injection.
type CheckCommand struct {
	// Optional pre-built services — when both are set, Exec() bypasses credential lookup so
	// callers (e.g. tests) can inject mocks without a live JFrog server.
	xraySvc *helperinternal.XrayService
	artSvc  *helperinternal.ArtifactoryService

	// Flag values — set by fluent setters from main.go Action callback.
	Image            string // Image reference (e.g., "myimage:latest" or "docker-local/myimage:latest")
	Repo             string // Artifactory repository key passed to ParseImageName; defaults to "docker-local" when empty
	ServerId         string // JFrog CLI server configuration ID
	Platform         string // Platform filter: "os/arch" (e.g., "linux/amd64") or OS only (e.g., "linux")
	FailOnVuln       bool   // Exit non-zero if any vulnerabilities found
	Output           string // Output format: "json" or "github-md"
	MinSeverity      string // Minimum severity to display: Low, Medium, High, Critical, Malicious
	Debug            bool   // Enable debug-level logging
	DockerRegistryURL string // Override URL for Docker registry (for direct manifest fetch)
	ProjectKey       string // Xray project key for violation queries (defaults to "default")
	MaliciousWatchName string // Xray watch that defines malicious packages (source of truth)
	NoFindings         bool   // Suppress Security Findings table in output
	AppName            string // Plugin name passed from main.go for footer rendering
	AppVersion         string // Plugin version passed from main.go for footer rendering
}

// NewCheckCommand returns a CheckCommand with defaults matching the CLI flag declarations.
func NewCheckCommand() *CheckCommand {
	return &CheckCommand{}
}

// SetXrayService injects a pre-built XrayService (e.g. a test mock).
// When paired with SetArtifactoryService, Exec() uses these instead of live credentials.
func (c *CheckCommand) SetXrayService(svc *helperinternal.XrayService) *CheckCommand {
	c.xraySvc = svc
	return c
}

// SetArtifactoryService injects a pre-built ArtifactoryService (e.g. a test mock).
// When paired with SetXrayService, Exec() uses these instead of live credentials.
func (c *CheckCommand) SetArtifactoryService(svc *helperinternal.ArtifactoryService) *CheckCommand {
	c.artSvc = svc
	return c
}

// Fluent setters for flag values — each returns *CheckCommand for chaining.
func (c *CheckCommand) SetImage(v string) *CheckCommand          { c.Image = v; return c }
func (c *CheckCommand) SetRepo(v string) *CheckCommand           { c.Repo = v; return c }
func (c *CheckCommand) SetServerId(v string) *CheckCommand       { c.ServerId = v; return c }
func (c *CheckCommand) SetPlatform(v string) *CheckCommand       { c.Platform = v; return c }
func (c *CheckCommand) SetFailOnVuln(v bool) *CheckCommand       { c.FailOnVuln = v; return c }
func (c *CheckCommand) SetOutput(v string) *CheckCommand         { c.Output = v; return c }
func (c *CheckCommand) SetMinSeverity(v string) *CheckCommand    { c.MinSeverity = v; return c }
func (c *CheckCommand) SetDebug(v bool) *CheckCommand            { c.Debug = v; return c }
func (c *CheckCommand) SetDockerRegistryURL(v string) *CheckCommand { c.DockerRegistryURL = v; return c }
func (c *CheckCommand) SetProjectKey(v string) *CheckCommand     { c.ProjectKey = v; return c }
func (c *CheckCommand) SetMaliciousWatchName(v string) *CheckCommand { c.MaliciousWatchName = v; return c }
func (c *CheckCommand) SetNoFindings(v bool) *CheckCommand           { c.NoFindings = v; return c }
func (c *CheckCommand) SetAppName(v string) *CheckCommand            { c.AppName = v; return c }
func (c *CheckCommand) SetAppVersion(v string) *CheckCommand         { c.AppVersion = v; return c }

// Exec runs the check pipeline with all configured parameters.
// When xraySvc and artSvc are both set (via SetXrayService/SetArtifactoryService),
// Exec bypasses credential lookup and uses the injected services directly — enabling
// unit tests without a live JFrog server.
func (c *CheckCommand) Exec() error {
	if c.xraySvc != nil && c.artSvc != nil {
		if c.MaliciousWatchName == "" {
			return fmt.Errorf("--malicious-watch-name is required")
		}
		output := c.Output
		if output == "" {
			output = "table"
		}
		projectKey := c.ProjectKey
		if projectKey == "" {
			projectKey = "default"
		}
		conf := &helperinternal.CheckConfiguration{
			ImageName:          c.Image,
			ServerId:           c.ServerId,
			Platform:           c.Platform,
			FailOnVuln:         c.FailOnVuln,
			Output:             output,
			Silent:             output == "github-md",
			MinSeverity:        c.MinSeverity,
			Debug:              c.Debug,
			DockerRegistryURL:  c.DockerRegistryURL,
			ProjectKey:         projectKey,
			MaliciousWatchName: c.MaliciousWatchName,
			NoFindings:         c.NoFindings,
			AppName:            c.AppName,
			AppVersion:         c.AppVersion,
		}
		repoKey, imageName, tag, err := helperinternal.ParseImageName(conf.ImageName, c.Repo)
		if err != nil {
			return fmt.Errorf("invalid image format: %w", err)
		}
		return helperinternal.RunCheckCommandFromConf(conf, repoKey, imageName, tag, c.artSvc.ArtifactoryURL(), c.xraySvc, c.artSvc)
	}

	// Normal CLI path: build a components.Context and delegate to RunCheckCommand.
	ctx := &components.Context{Arguments: []string{c.Image}}
	if c.Repo != "" {
		ctx.AddStringFlag("repo", c.Repo)
	}
	if c.ServerId != "" {
		ctx.AddStringFlag("server-id", c.ServerId)
	}
	if c.Platform != "" {
		ctx.AddStringFlag("platform", c.Platform)
	}
	ctx.AddBoolFlag("fail-on-vuln", c.FailOnVuln)
	if c.Output != "" {
		ctx.AddStringFlag("output", c.Output)
	}
	if c.MinSeverity != "" {
		ctx.AddStringFlag("min-severity", c.MinSeverity)
	}
	ctx.AddBoolFlag("debug", c.Debug)
	if c.DockerRegistryURL != "" {
		ctx.AddStringFlag("docker-registry-url", c.DockerRegistryURL)
	}
	if c.ProjectKey != "" {
		ctx.AddStringFlag("project-key", c.ProjectKey)
	}
	if c.MaliciousWatchName != "" {
		ctx.AddStringFlag("malicious-watch-name", c.MaliciousWatchName)
	}
	ctx.AddBoolFlag("no-findings", c.NoFindings)

	return helperinternal.RunCheckCommand(ctx, c.AppName, c.AppVersion)
}

// GetCheckCommand returns the component.Command registration for the "check" subcommand.
// It builds a CheckCommand from the components.Context flags and delegates to Exec().
func GetCheckCommand(appName, appVersion string) components.Command {
	return components.Command{
		Name:        "check",
		Description: "Checks existing vulnerability scans for a Docker image across platforms.",
		Aliases:     []string{"ck"},
		Arguments:   getCheckArguments(),
		Flags:       getCheckFlags(),
		EnvVars:     getCheckEnvVar(),
		Action: func(c *components.Context) error {
			return checkCmd(c, appName, appVersion)
		},
	}
}

// checkCmd is the original action callback — kept for backward compatibility with tests.
func checkCmd(c *components.Context, appName, appVersion string) error {
	if len(c.Arguments) == 0 {
		return fmt.Errorf("image name is required. Usage: check <image:tag>")
	}

	output := c.GetStringFlagValue("output")
	if output == "" {
		output = "table"
	}

	cmd := NewCheckCommand().
		SetImage(c.Arguments[0]).
		SetRepo(c.GetStringFlagValue("repo")).
		SetServerId(c.GetStringFlagValue("server-id")).
		SetPlatform(c.GetStringFlagValue("platform")).
		SetFailOnVuln(c.GetBoolFlagValue("fail-on-vuln")).
		SetOutput(output).
		SetMinSeverity(c.GetStringFlagValue("min-severity")).
		SetDebug(c.GetBoolFlagValue("debug")).
		SetDockerRegistryURL(c.GetStringFlagValue("docker-registry-url")).
		SetProjectKey(c.GetStringFlagValue("project-key")).
		SetMaliciousWatchName(c.GetStringFlagValue("malicious-watch-name")).
		SetNoFindings(c.GetBoolFlagValue("no-findings")).
		SetAppName(appName).
		SetAppVersion(appVersion)

	return cmd.Exec()
}

func getCheckArguments() []components.Argument {
	return []components.Argument{
		{
			Name:        "image",
			Description: "The Docker image name and tag (e.g., myimage:tag or repo/myimage:tag). If the repo is omitted, --repo is used.",
		},
	}
}

func getCheckFlags() []components.Flag {
	return []components.Flag{
		components.NewStringFlag(
			"repo",
			"Artifactory repository key containing the Docker image. Defaults to 'docker-local'.",
		),
		components.NewStringFlag(
			"server-id",
			"JFrog server configuration ID to use.",
		),
		components.NewStringFlag(
			"platform",
			"Filter results by platform (e.g., linux/amd64) or OS only (e.g., linux).",
		),
		components.NewBoolFlag(
			"fail-on-vuln",
			"Exit with error code if vulnerabilities are found.",
			components.WithBoolDefaultValue(false),
		),
		components.NewStringFlag(
			"output",
			"Output format: table (default), json, github-md (silent markdown for CI).",
		),
		components.NewStringFlag(
			"min-severity",
			"Minimum severity level to display in findings (Low, Medium, High, Critical, Malicious). Summary shows all severities.",
		),
		components.NewBoolFlag(
			"debug",
			"Enable debug-level logging for troubleshooting.",
			components.WithBoolDefaultValue(false),
		),
		components.NewStringFlag(
			"docker-registry-url",
			"Docker registry URL (e.g., https://company-docker-local.jfrog.io). If not specified, will be constructed from JFROG_URL.",
		),
		components.NewStringFlag(
			"project-key",
			"Xray project key for violation queries. Defaults to 'default' if not specified.",
		),
		components.NewStringFlag(
			"malicious-watch-name",
			"Xray watch that defines malicious packages (source of truth for malicious detection). Required.",
		),
		components.NewBoolFlag(
			"no-findings",
			"Suppress the Security Findings table in output. Summary counts and malicious findings are still shown.",
			components.WithBoolDefaultValue(false),
		),
	}
}

func getCheckEnvVar() []components.EnvVar {
	return []components.EnvVar{}
}

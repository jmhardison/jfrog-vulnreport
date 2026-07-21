package commands

import (
	"fmt"

	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	helperinternal "github.com/jmhardison/jfrog-vulnreport/internal"
)

// CheckCommand holds all parameters and dependencies for a vulnerability check invocation.
// Mirrors the build-deps-info pattern: a struct with fluent setters for dependency injection.
type CheckCommand struct {
	xrayManager any // *xray.XrayServicesManager (typed after xray import added)

	// Flag values — set by fluent setters from main.go Action callback.
	Image            string // Full image reference (e.g., "docker-local/myimage:latest")
	ServerId         string // JFrog CLI server configuration ID
	Platform         string // Platform filter in "os/arch" format (e.g., "linux/amd64")
	OS               string // OS filter (extracted from Platform if not set separately)
	FailOnVuln       bool   // Exit non-zero if any vulnerabilities found
	Output           string // Output format: "json" or "github-md"
	MinSeverity      string // Minimum severity to display: Low, Medium, High, Critical, Malicious
	ShowFindings     bool   // Include detailed findings table in markdown output
	DebugPaths       bool   // Log artifact discovery paths for troubleshooting
	DockerRegistryURL string // Override URL for Docker registry (for direct manifest fetch)
	ProjectKey       string // Xray project key for violation queries (defaults to "default")
	WatchName        string // JFrog Xray watch name — filters violations to relevant ones
	MaliciousWatchName string // Xray watch that defines malicious packages (source of truth)
}

// NewCheckCommand returns a CheckCommand with defaults matching the CLI flag declarations.
func NewCheckCommand() *CheckCommand {
	return &CheckCommand{ShowFindings: true}
}

// SetXrayServicesManager injects the authenticated Xray SDK manager.
// Mirrors BuildDepsInfo.SetServicesManager in jfrog/jfrog-cli-plugins/build-deps-info.
func (c *CheckCommand) SetXrayServicesManager(xrayManager any) *CheckCommand {
	c.xrayManager = xrayManager
	return c
}

// Fluent setters for flag values — each returns *CheckCommand for chaining.
func (c *CheckCommand) SetImage(v string) *CheckCommand          { c.Image = v; return c }
func (c *CheckCommand) SetServerId(v string) *CheckCommand       { c.ServerId = v; return c }
func (c *CheckCommand) SetPlatform(v string) *CheckCommand       { c.Platform = v; return c }
func (c *CheckCommand) SetOS(v string) *CheckCommand             { c.OS = v; return c }
func (c *CheckCommand) SetFailOnVuln(v bool) *CheckCommand       { c.FailOnVuln = v; return c }
func (c *CheckCommand) SetOutput(v string) *CheckCommand         { c.Output = v; return c }
func (c *CheckCommand) SetMinSeverity(v string) *CheckCommand    { c.MinSeverity = v; return c }
func (c *CheckCommand) SetShowFindings(v bool) *CheckCommand     { c.ShowFindings = v; return c }
func (c *CheckCommand) SetDebugPaths(v bool) *CheckCommand       { c.DebugPaths = v; return c }
func (c *CheckCommand) SetDockerRegistryURL(v string) *CheckCommand { c.DockerRegistryURL = v; return c }
func (c *CheckCommand) SetProjectKey(v string) *CheckCommand     { c.ProjectKey = v; return c }
func (c *CheckCommand) SetWatchName(v string) *CheckCommand      { c.WatchName = v; return c }
func (c *CheckCommand) SetMaliciousWatchName(v string) *CheckCommand { c.MaliciousWatchName = v; return c }

// Exec runs the check pipeline with all configured parameters.
func (c *CheckCommand) Exec() error {
	// Build a components.Context that bridges our CheckCommand fields into the
	// internal package's expected interface. This mirrors what the framework does
	// when wiring up Action callbacks from CLI flag parsing.
	ctx := &components.Context{Arguments: []string{c.Image}}
	if c.ServerId != "" {
		ctx.AddStringFlag("server-id", c.ServerId)
	}
	if c.Platform != "" {
		ctx.AddStringFlag("platform", c.Platform)
	}
	if c.OS != "" {
		ctx.AddStringFlag("os", c.OS)
	}
	if c.FailOnVuln {
		ctx.AddBoolFlag("fail-on-vuln", true)
	}
	if c.Output != "" {
		ctx.AddStringFlag("output", c.Output)
	}
	if c.MinSeverity != "" {
		ctx.AddStringFlag("min-severity", c.MinSeverity)
	}
	ctx.AddBoolFlag("show-findings", c.ShowFindings)
	ctx.AddBoolFlag("debug-paths", c.DebugPaths)
	if c.DockerRegistryURL != "" {
		ctx.AddStringFlag("docker-registry-url", c.DockerRegistryURL)
	}
	if c.ProjectKey != "" {
		ctx.AddStringFlag("project-key", c.ProjectKey)
	}
	if c.WatchName != "" {
		ctx.AddStringFlag("watch-name", c.WatchName)
	}
	if c.MaliciousWatchName != "" {
		ctx.AddStringFlag("malicious-watch-name", c.MaliciousWatchName)
	}

	return helperinternal.RunCheckCommand(ctx)
}

// GetCheckCommand returns the component.Command registration for the "check" subcommand.
// It builds a CheckCommand from the components.Context flags and delegates to Exec().
func GetCheckCommand() components.Command {
	return components.Command{
		Name:        "check",
		Description: "Checks existing vulnerability scans for a Docker image across platforms.",
		Aliases:     []string{"ck"},
		Arguments:   getCheckArguments(),
		Flags:       getCheckFlags(),
		EnvVars:     getCheckEnvVar(),
		Action: func(c *components.Context) error {
			return checkCmd(c)
		},
	}
}

// checkCmd is the original action callback — kept for backward compatibility with tests.
func checkCmd(c *components.Context) error {
	if len(c.Arguments) == 0 {
		return fmt.Errorf("image name is required. Usage: check <image:tag>")
	}

	output := c.GetStringFlagValue("output")
	if output == "" {
		output = "json" // Default to JSON
	}

	cmd := NewCheckCommand().
		SetImage(c.Arguments[0]).
		SetServerId(c.GetStringFlagValue("server-id")).
		SetPlatform(c.GetStringFlagValue("platform")).
		SetOS(c.GetStringFlagValue("os")).
		SetFailOnVuln(c.GetBoolFlagValue("fail-on-vuln")).
		SetOutput(output).
		SetMinSeverity(c.GetStringFlagValue("min-severity")).
		SetShowFindings(c.GetBoolFlagValue("show-findings")).
		SetDebugPaths(c.GetBoolFlagValue("debug-paths")).
		SetDockerRegistryURL(c.GetStringFlagValue("docker-registry-url")).
		SetProjectKey(c.GetStringFlagValue("project-key")).
		SetWatchName(c.GetStringFlagValue("watch-name")).
		SetMaliciousWatchName(c.GetStringFlagValue("malicious-watch-name"))

	return cmd.Exec()
}

func getCheckArguments() []components.Argument {
	return []components.Argument{
		{
			Name:        "image",
			Description: "The Docker image name and tag (e.g., myrepo/myimage:tag).",
		},
	}
}

func getCheckFlags() []components.Flag {
	return []components.Flag{
		components.NewStringFlag(
			"server-id",
			"JFrog server configuration ID to use.",
		),
		components.NewStringFlag(
			"platform",
			"Filter results by platform architecture (e.g., amd64, arm64).",
		),
		components.NewStringFlag(
			"os",
			"Filter results by operating system (e.g., linux, windows).",
		),
		components.NewBoolFlag(
			"fail-on-vuln",
			"Exit with error code if vulnerabilities are found.",
			components.WithBoolDefaultValue(false),
		),
		components.NewStringFlag(
			"output",
			"Output format: json (default), github-md (silent markdown for GitHub).",
		),
		components.NewStringFlag(
			"min-severity",
			"Minimum severity level to display in findings (Low, Medium, High, Critical, Malicious). Summary shows all severities.",
		),
		components.NewBoolFlag(
			"show-findings",
			"Display detailed security findings table (default: true).",
			components.WithBoolDefaultValue(true),
		),
		components.NewBoolFlag(
			"debug-paths",
			"Enable debug mode to explore repository structure.",
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
			"watch-name",
			"JFrog Xray watch name to filter violations (e.g., dockerlocal-malicious-critical). Required.",
		),
		components.NewStringFlag(
			"malicious-watch-name",
			"Xray watch that defines malicious packages (source of truth for malicious detection). Required.",
		),
	}
}

func getCheckEnvVar() []components.EnvVar {
	return []components.EnvVar{}
}

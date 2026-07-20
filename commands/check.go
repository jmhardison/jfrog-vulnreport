package commands

import (
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	helperinternal "github.com/jmhardison/jfrog-vulnreport/internal"
)

// GetCheckCommand returns the CLI command definition for the 'check' subcommand.
// It registers all CLI flags, arguments, and environment variables needed to run a vulnerability check.
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

// checkCmd is the action handler invoked by JFrog CLI when the 'check' command runs.
// It delegates all logic to the internal package's RunCheckCommand function.
func checkCmd(c *components.Context) error {
	return helperinternal.RunCheckCommand(c)
}

// getCheckArguments defines the positional arguments for the check command.
// Currently only requires a single image:tag argument.
func getCheckArguments() []components.Argument {
	return []components.Argument{
		{
			Name:        "image",
			Description: "The Docker image name and tag (e.g., myrepo/myimage:tag).",
		},
	}
}

// getCheckFlags defines all CLI flags available to the check command.
// Flag definitions include string, boolean, and optional-value variants with default values where applicable.
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

// getCheckEnvVar defines environment variables that can override CLI flags.
// Currently none are defined; all configuration is done via flags only.
func getCheckEnvVar() []components.EnvVar {
	return []components.EnvVar{}
}

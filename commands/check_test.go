package commands

import (
	"testing"

	artAuth "github.com/jfrog/jfrog-client-go/artifactory/auth"
	"github.com/jfrog/jfrog-client-go/http/jfroghttpclient"
	xrayAuth "github.com/jfrog/jfrog-client-go/xray/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	helperinternal "github.com/jmhardison/jfrog-vulnreport/internal"
)

func TestGetCheckCommand_Wiring(t *testing.T) {
	cmd := GetCheckCommand("vulnreport", "v0.1.5")
	assert.Equal(t, "check", cmd.Name)
	assert.NotNil(t, cmd.Action)
}

func TestGetCheckCommand_AliasRegistered(t *testing.T) {
	cmd := GetCheckCommand("vulnreport", "vtest")
	assert.Equal(t, "check", cmd.Name, "primary command name must be 'check'")
	assert.Contains(t, cmd.Aliases, "ck", "'ck' alias must be registered so both 'check' and 'ck' dispatch the same action")
}

func TestCheckCmd_RequiresImageArgument(t *testing.T) {
	err := checkCmd(&components.Context{}, "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "image name is required")
}

func TestNewCheckCommand(t *testing.T) {
	cmd := NewCheckCommand()
	require.NotNil(t, cmd)
	assert.Empty(t, cmd.Image)
	assert.Empty(t, cmd.Repo)
	assert.Empty(t, cmd.Output)
	assert.Empty(t, cmd.MaliciousWatchName)
	assert.False(t, cmd.FailOnVuln)
	assert.False(t, cmd.NoFindings)
	assert.Empty(t, cmd.SaveOutput)
}

func TestCheckCommand_FluentSetters(t *testing.T) {
	cmd := NewCheckCommand().
		SetImage("myapp:v1").
		SetRepo("docker-prod-local").
		SetServerId("my-server").
		SetPlatform("linux/amd64").
		SetFailOnVuln(true).
		SetOutput("github-md").
		SetMinSeverity("High").
		SetDebug(true).
		SetDockerRegistryURL("https://registry.example.com").
		SetProjectKey("my-project").
		SetMaliciousWatchName("org-malicious-watch").
		SetNoFindings(true).
		SetSaveOutput("json,github-md").
		SetAppName("vulnreport").
		SetAppVersion("vtest")

	assert.Equal(t, "myapp:v1", cmd.Image)
	assert.Equal(t, "docker-prod-local", cmd.Repo)
	assert.Equal(t, "my-server", cmd.ServerId)
	assert.Equal(t, "linux/amd64", cmd.Platform)
	assert.True(t, cmd.FailOnVuln)
	assert.Equal(t, "github-md", cmd.Output)
	assert.Equal(t, "High", cmd.MinSeverity)
	assert.True(t, cmd.Debug)
	assert.Equal(t, "https://registry.example.com", cmd.DockerRegistryURL)
	assert.Equal(t, "my-project", cmd.ProjectKey)
	assert.Equal(t, "org-malicious-watch", cmd.MaliciousWatchName)
	assert.True(t, cmd.NoFindings)
	assert.Equal(t, "json,github-md", cmd.SaveOutput)
	assert.Equal(t, "vulnreport", cmd.AppName)
	assert.Equal(t, "vtest", cmd.AppVersion)
}

func TestExec_DI_RequiresMaliciousWatchName(t *testing.T) {
	// When both services are injected, Exec must reject an empty MaliciousWatchName
	// before any API calls are made — no live server required.
	client, err := jfroghttpclient.JfrogClientBuilder().Build()
	require.NoError(t, err)

	artDetails := artAuth.NewArtifactoryDetails()
	artDetails.SetUrl("http://test-host/")
	xrayDetails := xrayAuth.NewXrayDetails()
	xrayDetails.SetUrl("http://test-host/")

	cmd := NewCheckCommand().
		SetImage("myapp:v1").
		SetXrayService(helperinternal.NewXrayService(client, xrayDetails)).
		SetArtifactoryService(helperinternal.NewArtifactoryService(client, artDetails))
	// MaliciousWatchName deliberately left empty

	err = cmd.Exec()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "malicious-watch-name")
}

func TestGetCheckFlags_AllFlagsPresent(t *testing.T) {
	flags := getCheckFlags()
	registered := make(map[string]bool, len(flags))
	for _, f := range flags {
		registered[f.GetName()] = true
	}

	expected := []string{
		"repo", "server-id", "platform", "fail-on-vuln", "output",
		"min-severity", "debug", "docker-registry-url",
		"project-key", "malicious-watch-name", "no-findings", "save-output",
	}
	for _, name := range expected {
		assert.True(t, registered[name], "flag %q must be registered in getCheckFlags()", name)
	}
}

func TestGetCheckArguments_ImageArgument(t *testing.T) {
	args := getCheckArguments()
	require.Len(t, args, 1, "check command must declare exactly one positional argument")
	assert.Equal(t, "image", args[0].Name)
	assert.NotEmpty(t, args[0].Description)
}

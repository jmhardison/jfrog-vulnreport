package commands

import (
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	"github.com/stretchr/testify/assert"
)

func TestGetCheckCommand_Wiring(t *testing.T) {
	cmd := GetCheckCommand("vulnreport", "v0.1.5")
	assert.Equal(t, "check", cmd.Name)
	assert.NotNil(t, cmd.Action)
}

func TestCheckCmd_RequiresImageArgument(t *testing.T) {
	err := checkCmd(&components.Context{}, "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "image name is required")
}

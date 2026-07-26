package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetApp(t *testing.T) {
	app := getApp()
	assert.Equal(t, appName, app.Name)
	assert.Equal(t, appVersion, app.Version)
	assert.NotEmpty(t, app.Description)
	assert.NotEmpty(t, app.Commands, "plugin must register at least one command")
}

func TestGetCommands(t *testing.T) {
	cmds := getCommands()
	require.Len(t, cmds, 1, "exactly one command should be registered")
	assert.Equal(t, "check", cmds[0].Name)
	assert.NotNil(t, cmds[0].Action, "check command must have an action handler")
}

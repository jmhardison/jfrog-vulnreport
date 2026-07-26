package main

import (
	"github.com/jfrog/jfrog-cli-core/v2/plugins"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	"github.com/jmhardison/jfrog-vulnreport/commands"
)

const (
	appName    = "vulnreport"
	appVersion = "v0.1.10"
)

func main() {
	plugins.PluginMain(getApp())
}

func getApp() components.App {
	app := components.App{}
	app.Name = appName
	app.Description = "JFrog vulnerability report tool for Docker images."
	app.Version = appVersion
	app.Commands = getCommands()
	return app
}

func getCommands() []components.Command {
	return []components.Command{
		commands.GetCheckCommand(appName, appVersion),
	}
}

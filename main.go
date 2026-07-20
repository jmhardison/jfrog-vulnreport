package main

import (
	"github.com/jfrog/jfrog-cli-core/v2/plugins"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	"github.com/jmhardison/jfrog-vulnreport/commands"
)

// main is the entry point for the JFrog CLI plugin. It starts the plugin framework
// with a configured App that declares the 'check' command as the only subcommand.
func main() {
	plugins.PluginMain(getApp())
}

// getApp builds and returns the plugin application configuration, including its name,
// description, version, and list of registered commands.
func getApp() components.App {
	app := components.App{}
	app.Name = "jfrog-vulnreport"
	app.Description = "JFrog vulnerability report tool for Docker images."
	app.Version = "v0.1.2"
	app.Commands = getCommands()
	return app
}

// getCommands returns the list of plugin commands. Currently registers only the 'check' command.
func getCommands() []components.Command {
	return []components.Command{
		commands.GetCheckCommand(),
	}
}

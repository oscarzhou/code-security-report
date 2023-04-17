package cmd

import "fmt"

const TOOL_VERSION = "0.1.8"

// VersionCommand is the command to get the version of the tool
type VersionCommand struct {
}

func (cmd *VersionCommand) Run() error {
	fmt.Println(TOOL_VERSION)
	return nil
}

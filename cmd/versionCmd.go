package cmd

import "fmt"

const VERSION = "0.2.0"

// VersionCommand is the command to get the version of the tool
type VersionCommand struct {
}

func (cmd *VersionCommand) Run() error {
	fmt.Println(VERSION)
	return nil
}

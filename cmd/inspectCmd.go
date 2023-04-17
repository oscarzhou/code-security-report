package cmd

import (
	"fmt"
	"os/exec"
)

type InspectCommand struct {
	TargetDir string `short:"t" long:"target" description:"Target directory to inspect" default:"." type:"path"`
}

func (c *InspectCommand) Run() error {
	if c.TargetDir == "" {
		c.TargetDir = "/"
	}

	byteRet, err := exec.Command("ls", "-lha", c.TargetDir).Output()
	if err != nil {
		return err
	}

	fmt.Println(string(byteRet))
	return nil
}

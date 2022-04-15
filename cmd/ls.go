package cmd

import (
	"fmt"
	"log"
	"os/exec"
)

func List(targetDir string) {
	if targetDir == "" {
		targetDir = "/"
	}

	b, err := exec.Command("ls", "-lha", targetDir).Output()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(b))
}

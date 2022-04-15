package cmd

import "fmt"

type Version struct {
	Major int
	Minor int
	Patch int
}

func GetVersion() {
	version := Version{
		Major: 0,
		Minor: 1,
		Patch: 3,
	}

	fmt.Printf("version: %d.%d.%d\n", version.Major, version.Minor, version.Patch)
}

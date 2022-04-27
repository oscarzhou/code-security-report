package cmd

import "fmt"

func Help() {
	help := `
Usage: scanreport COMMAND [OPTIONS]

A tool for analyzing various code security reports (i.e. Snyk, Trivy). Inspired by Github Action Integration

Commands:
	export	Export the summary/diff report to html file
	ls		List the files under the specific directory
	version 	Show the ScanReport version information
	summary		Return the summary of a security scan report

Run 'scanreport COMMAND --help' for more information on a command.
	`

	fmt.Println(help)
}

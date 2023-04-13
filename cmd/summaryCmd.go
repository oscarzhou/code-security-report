package cmd

import (
	"errors"

	"github.com/oscarzhou/code-security-report/scan"
)

type SummaryCommand struct {
	ReportType     string `kong:"args='',help='Set the report type',default='snyk',enum='snyk,trivy,gosec'"`
	Path           string `kong:"args='',help='Set the path to current file',default='',example='/path/to/current-file.json'"`
	Export         bool   `kong:",help='Whether to export the result to a html file',default='false'"`
	OutputType     string `kong:"args='',help='Set the output type',default='table',enum='matrix,table'"`
	ExportFilename string `kong:"args='',help='Set the filename of the exported html file',default='',example='report.html'"`
}

func (c *SummaryCommand) Run() error {
	// validate the input
	if c.ReportType == "" {
		return errors.New("report type not set")
	}

	if c.Path == "" {
		return errors.New("path not set")
	}

	// create the scanner
	var (
		securityScanner scan.Scanner
		err             error
	)
	switch c.ReportType {
	case "snyk":
		securityScanner, err = scan.NewSnykScanner(c.Path)

	case "trivy":
		securityScanner, err = scan.NewTrivyScanner(c.Path)

	case "gosec":

	default:
		return errors.New("unknown report type")
	}

	if err != nil {
		return err
	}

	// export the result to a html file
	if c.Export {
		err = securityScanner.Export(c.OutputType, c.ExportFilename)
		if err != nil {
			return err
		}

	} else {
		// scan the report and output the result
		result, err := securityScanner.Scan()
		if err != nil {
			return err
		}
		result.Output(c.OutputType)
	}

	return nil
}

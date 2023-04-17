package cmd

import (
	"errors"
	"fmt"

	"github.com/oscarzhou/code-security-report/scan"
)

type DiffCommand struct {
	ReportType     string `kong:"args='',help='Set the report type',default='snyk',enum='snyk,trivy,gosec'"`
	Path           string `kong:"args='',help='Set the path to current file',default='',type='path',example='/path/to/current-file.json'"`
	CompareTo      string `kong:"args='',help='Set the path to previous file',default='',example='/path/to/previous-file.json'"`
	Export         bool   `kong:"help='Whether to export the result to a html file',default='false'"`
	OutputType     string `kong:"args='',help='Set the output type',default='table',enum='matrix,table'"`
	ExportFilename string `kong:"args='',help='Set the filename of the exported html file',default='',example='report.html'"`
}

func (c *DiffCommand) Run() error {
	// validate the input
	if c.ReportType == "" {
		return errors.New("report type not set")
	}

	if c.Path == "" {
		return errors.New("path not set")
	}

	if c.CompareTo == "" {
		return errors.New("compare to path not set")
	}

	var (
		securityScanner           scan.Scanner
		comparedToSecurityScanner scan.Scanner
		err                       error
	)

	// create the scanner
	switch c.ReportType {
	case "snyk":
		securityScanner, err = scan.NewSnykScanner(c.Path)
		if err != nil {
			return fmt.Errorf("failed to create snyk scanner: %w", err)
		}

		comparedToSecurityScanner, err = scan.NewSnykScanner(c.CompareTo)
		if err != nil && err != scan.ErrNullFile {
			return fmt.Errorf("failed to create snyk compared scanner: %w", err)
		}

	case "trivy":
		securityScanner, err = scan.NewTrivyScanner(c.Path)
		if err != nil {
			return fmt.Errorf("failed to create trivy scanner: %w", err)
		}

		comparedToSecurityScanner, err = scan.NewTrivyScanner(c.CompareTo)
		if err != nil {
			return fmt.Errorf("failed to create trivy compared scanner: %w", err)
		}

	case "gosec":

	default:
		return errors.New("unknown report type")
	}

	if err != nil {
		return err
	}

	// export the result to a html file
	if c.Export {
		err = securityScanner.ExportDiff(comparedToSecurityScanner, c.OutputType, c.ExportFilename)
		if err != nil {
			return err
		}
	} else {
		result, err := securityScanner.Diff(comparedToSecurityScanner)
		if err != nil {
			return err
		}
		result.Output(c.OutputType)
	}

	return nil
}

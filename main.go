package main

import (
	"flag"
	"log"
	"os"

	"github.com/oscarzhou/scan-report/cmd"
	"github.com/oscarzhou/scan-report/scan"
)

func main() {
	command := os.Args[1]
	os.Args = append(os.Args[:1], os.Args[2:]...)

	var config GlobalConfig
	flag.StringVar(&config.ReportType, "report-type", "", "snyk,trivy,gosec")
	flag.StringVar(&config.Path, "path", "", "/path/to/current-file.json")
	flag.StringVar(&config.CompareTo, "compare-to", "", "/path/to/previous-file.json")
	flag.StringVar(&config.OutputType, "output-type", "", "matrix")
	flag.Parse()

	switch command {
	case "version":
		cmd.GetVersion()
		break

	case "summary":
		if config.ReportType == "" {
			log.Fatal("report type not set")
		} else {
			if !(config.ReportType == "snyk" || config.ReportType == "trivy" || config.ReportType == "gosec") {
				log.Fatal("unrecoginize report type")
			}
		}

		if config.Path == "" {
			log.Fatal("path not set")
		}

		var (
			s   scan.Scanner
			err error
		)
		switch config.ReportType {
		case "snyk":
			s, err = scan.NewSnykScanner(config.Path)

		case "trivy":
			s, err = scan.NewTrivyScanner(config.Path)

		case "gosec":

		}

		if err != nil {
			log.Fatal(err)
		}

		result, err := s.Scan()
		if err != nil {
			log.Fatal(err)
		}

		result.Output(config.OutputType)

	case "diff":
		if config.ReportType == "" {
			log.Fatal("report type not set")
		} else {
			if !(config.ReportType == "snyk" || config.ReportType == "trivy" || config.ReportType == "gosec") {
				log.Fatal("unrecoginize report type")
			}
		}

		if config.Path == "" {
			log.Fatal("path not set")
		}

		if config.CompareTo == "" {
			log.Fatal("compared path not set")
		}

		var (
			s    scan.Scanner
			base scan.Scanner
			err  error
		)

		switch config.ReportType {
		case "snyk":
			s, err = scan.NewSnykScanner(config.Path)
			if err != nil {
				log.Fatal(err)
			}

			base, err = scan.NewSnykScanner(config.CompareTo)
			if err != nil {
				log.Fatal(err)
			}

		case "trivy":
			s, err = scan.NewTrivyScanner(config.Path)
			if err != nil {
				log.Fatal(err)
			}

			base, err = scan.NewTrivyScanner(config.CompareTo)
			if err != nil {
				log.Fatal(err)
			}

		case "gosec":

		}

		result, err := s.Diff(base)
		if err != nil {
			log.Fatal(err)
		}

		result.Output(config.OutputType)

	case "ls":
		cmd.List(config.Path)
		break

	case "help":
		cmd.Help()
		break
	}
}

type GlobalConfig struct {
	ReportType string
	Path       string
	OutputType string
	CompareTo  string
}

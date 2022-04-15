package main

import (
	"flag"
	"log"
	"os"

	"github.com/oscarzhou/scan-report/cmd"
	"github.com/oscarzhou/scan-report/scan"
)

func main() {
	var config GlobalConfig
	flag.StringVar(&config.ReportType, "report-type", "", "snyk,trivy,gosec")
	flag.StringVar(&config.Path, "path", "", "/path/to/file.json")
	flag.StringVar(&config.OutputType, "output-type", "", "matrix")
	flag.Parse()

	args := flag.Args()
	switch args[0] {
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

		dat, err := os.ReadFile(config.Path)
		if err != nil {
			log.Fatalf("file %s not found ", config.Path)
		}

		var s scan.Scanner
		switch config.ReportType {
		case "snyk":
			s = &scan.SnykScanner{}
		case "trivy":
			s = &scan.TrivyScanner{}
		case "gosec":

		}

		result, err := s.Scan(dat)
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
}

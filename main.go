package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/oscarzhou/scan-report/scan"
)

func main() {

	var config GlobalConfig
	flag.StringVar(&config.Action, "action", "summary,ls", "summary")
	flag.StringVar(&config.ReportType, "report-type", "snyk,trivy,gosec", "")
	flag.StringVar(&config.Path, "path", "/path/to/file.json", "")
	flag.Parse()

	switch config.Action {
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

		result.Summarize()
	case "ls":
		b, err := exec.Command("ls", "-lha", config.Path).Output()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(b))

	}

}

type GlobalConfig struct {
	Action     string
	ReportType string
	Path       string
}

package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/oscarzhou/scan-report/prototypes"
	"github.com/oscarzhou/scan-report/templates"
)

type SnykScanner struct {
	Snyk                   prototypes.Snyk
	ScannedVulnerabilities map[string]struct{}
}

func NewSnykScanner(path string) (*SnykScanner, error) {
	snyk := &SnykScanner{
		ScannedVulnerabilities: make(map[string]struct{}),
	}

	dat, err := os.ReadFile(path)
	if err != nil {
		return snyk, fmt.Errorf("file %s not found ", path)
	}

	err = json.Unmarshal(dat, &snyk.Snyk)
	if err != nil {
		return snyk, err
	}
	return snyk, nil
}

func (s *SnykScanner) Scan() (Result, error) {
	var result Result
	langs := make(map[string]struct{})

	for _, vuln := range s.Snyk.Vulnerabilities {
		_, ok := s.ScannedVulnerabilities[vuln.ID]
		if ok {
			continue
		}

		s.ScannedVulnerabilities[vuln.ID] = struct{}{}

		langs[vuln.Language] = struct{}{}

		if vuln.Severity == "critical" {
			result.Critical++
		} else if vuln.Severity == "high" {
			result.High++
		} else if vuln.Severity == "medium" {
			result.Medium++
		} else if vuln.Severity == "low" {
			result.Low++
		} else if vuln.Severity == "unknown" {
			result.Unknown++
		}

		if vuln.IsPatchable || vuln.IsUpgradable {
			if vuln.Severity == "critical" {
				result.FixableCritical++
			} else if vuln.Severity == "high" {
				result.FixableHigh++
			} else if vuln.Severity == "medium" {
				result.FixableMedium++
			} else if vuln.Severity == "low" {
				result.FixableLow++
			} else if vuln.Severity == "unknown" {
				result.FixableUnknown++
			}
		}
	}
	result.GetTotal()
	result.ScannedObjects = s.Snyk.DependencyCount
	if result.Total > 0 {
		result.Status = RESULT_FAILURE
	} else {
		result.Status = RESULT_SUCCESS
	}

	for lang := range langs {
		result.Languages = append(result.Languages, lang)
	}

	result.Summary = s.getSummary()
	result.SetSummary()

	return result, nil
}

func (s *SnykScanner) Diff(base Scanner) (DiffResult, error) {
	var result DiffResult

	// get base result
	baseResult, err := base.Scan()
	if err != nil {
		return result, err
	}

	result.Base = baseResult

	// get short vulnerabilities of current scanner
	vulns := s.getShortVulnerabilities()

	// get short vulnerabilities of base scanner
	compared, ok := base.(*SnykScanner)
	if !ok {
		return result, errors.New("assert Snyk error")
	}

	baseVulns := compared.getShortVulnerabilities()

	var (
		fixed    Result
		newFound Result
	)

	// scan the fixed vulnerabilities
	for _, baseVuln := range baseVulns {
		matched := false
		for _, currentVuln := range vulns {
			if baseVuln.ID == currentVuln.ID {
				matched = true
				break
			}
		}

		if !matched {
			if baseVuln.Severity == "critical" {
				fixed.Critical++
			} else if baseVuln.Severity == "high" {
				fixed.High++
			} else if baseVuln.Severity == "medium" {
				fixed.Medium++
			} else if baseVuln.Severity == "low" {
				fixed.Low++
			} else if baseVuln.Severity == "unknown" {
				fixed.Unknown++
			}
		}
	}
	fixed.GetTotal()
	fixed.Summary = s.getSummary()
	fixed.SetSummary()
	result.Fixed = fixed

	// scan the new vulnerabilities
	for _, currentVuln := range vulns {
		matched := false
		for _, baseVuln := range baseVulns {
			if baseVuln.ID == currentVuln.ID {
				matched = true
				break
			}
		}

		_, exist := compared.ScannedVulnerabilities[currentVuln.ID]

		if !matched && !exist {
			if currentVuln.Severity == "critical" {
				newFound.Critical++
			} else if currentVuln.Severity == "high" {
				newFound.High++
			} else if currentVuln.Severity == "medium" {
				newFound.Medium++
			} else if currentVuln.Severity == "low" {
				newFound.Low++
			} else if currentVuln.Severity == "unknown" {
				newFound.Unknown++
			}
		}
	}
	newFound.GetTotal()
	newFound.Summary = s.getSummary()
	newFound.SetSummary()
	result.NewFound = newFound

	if result.NewFound.Total == 0 {
		result.Status = RESULT_SUCCESS
	} else {
		result.Status = RESULT_FAILURE
	}

	result.Summarize()
	return result, nil
}

func (s *SnykScanner) getShortVulnerabilities() []prototypes.ShortSnykVulnerability {
	var vulns []prototypes.ShortSnykVulnerability
	for _, v := range s.Snyk.Vulnerabilities {
		_, ok := s.ScannedVulnerabilities[v.ID]
		if ok {
			continue
		}

		s.ScannedVulnerabilities[v.ID] = struct{}{}
		vulns = append(vulns, prototypes.ShortSnykVulnerability{
			ID:         v.ID,
			ModuleName: v.ModuleName,
			Severity:   v.Severity,
			CvssScore:  v.CvssScore,
			Title:      v.Title,
			Version:    v.Version,
			FixedIn:    v.FixedIn,
		})

	}
	return vulns
}

func (s *SnykScanner) getSummary() string {
	// build summary
	stringBuilder := ""
	if s.Snyk.DependencyCount > 0 {
		stringBuilder = fmt.Sprintf("Tested %d dependencies for known issues.", s.Snyk.DependencyCount)
	}

	return stringBuilder
}

func (s *SnykScanner) ClearCache() {
	s.ScannedVulnerabilities = make(map[string]struct{})
}

func (s *SnykScanner) Export(outputType, filename string) error {
	result, err := s.Scan()
	if err != nil {
		return err
	}

	s.ClearCache()

	vulns := s.getShortVulnerabilities()

	snykTmpl := prototypes.SnykTemplate{
		Name:            s.Snyk.ProjectName,
		Languages:       result.Languages,
		Vulnerabilities: vulns,
		Critical:        result.Critical,
		High:            result.High,
		Medium:          result.Medium,
		Low:             result.Low,
		Unknown:         result.Unknown,
		Total:           result.Total,
	}

	name := filename
	if filename == "" {
		name = fmt.Sprintf("scan-report-%s-%d.html", snykTmpl.Name, time.Now().Unix())
		name = strings.ReplaceAll(name, "/", "-")
	} else {
		if !strings.HasSuffix(name, ".html") {
			name = fmt.Sprintf("%s.html", name)
		}
	}

	f, err := os.OpenFile("./output/"+name, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	funcs := template.FuncMap{"join": strings.Join}
	switch outputType {
	case "table":
		tmpl, err := template.New(templates.SNYK_SUMMARY_HTML_TABLE).Funcs(funcs).ParseFiles("templates/" + templates.SNYK_SUMMARY_HTML_TABLE)
		if err != nil {
			return err
		}

		err = tmpl.Execute(f, &snykTmpl)
		if err != nil {
			return err
		}

	case "list":

	}

	return nil
}

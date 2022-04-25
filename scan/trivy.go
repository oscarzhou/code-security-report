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

type TrivyScanner struct {
	Trivy                  prototypes.Trivy
	ScannedVulnerabilities map[string]struct{}
	ScannedTargets         map[string][5]int64
}

func NewTrivyScanner(path string) (*TrivyScanner, error) {
	trivy := &TrivyScanner{
		ScannedVulnerabilities: make(map[string]struct{}),
		ScannedTargets:         make(map[string][5]int64),
	}

	dat, err := os.ReadFile(path)
	if err != nil {
		return trivy, fmt.Errorf("file %s not found ", path)
	}

	err = json.Unmarshal(dat, &trivy.Trivy)
	if err != nil {
		return trivy, err
	}
	return trivy, nil
}

func (s *TrivyScanner) Scan() (Result, error) {
	var result Result

	for _, res := range s.Trivy.Results {
		counts := [5]int64{0, 0, 0, 0, 0}
		for _, vuln := range res.Vulnerabilities {
			vulnID := getVulnerabilityID(res.Target, vuln.VulnerabilityID)

			_, ok := s.ScannedVulnerabilities[vulnID]
			if ok {
				continue
			}

			s.ScannedVulnerabilities[vulnID] = struct{}{}

			severity := strings.ToLower(vuln.Severity)
			if severity == "critical" {
				result.Critical++
				counts[0]++
			} else if severity == "high" {
				result.High++
				counts[1]++
			} else if severity == "medium" {
				result.Medium++
				counts[2]++
			} else if severity == "low" {
				result.Low++
				counts[3]++
			} else if severity == "unknown" {
				result.Unknown++
				counts[4]++
			}

			if vuln.FixedVersion != "" {
				if severity == "critical" {
					result.FixableCritical++
				} else if severity == "high" {
					result.FixableHigh++
				} else if severity == "medium" {
					result.FixableMedium++
				} else if severity == "low" {
					result.FixableLow++
				} else if severity == "unknown" {
					result.FixableUnknown++
				}
			}
		}

		s.ScannedTargets[res.Target] = counts
	}

	result.GetTotal()
	result.ScannedObjects = int64(len(s.Trivy.Results))
	if result.Total > 0 {
		result.Status = RESULT_FAILURE
	} else {
		result.Status = RESULT_SUCCESS
	}

	result.Summary = s.getSummary()
	result.SetSummary()

	return result, nil
}

func getVulnerabilityID(target, id string) string {
	return strings.Join([]string{target, id}, "-")
}

func (s *TrivyScanner) Diff(base Scanner) (DiffResult, error) {
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
	compared, ok := base.(*TrivyScanner)
	if !ok {
		return result, errors.New("assert Trivy error")
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

		_, ok := s.ScannedTargets[currentVuln.Target]
		if !ok {
			s.ScannedTargets[currentVuln.Target] = [5]int64{0, 0, 0, 0, 0}
		}
		counts := s.ScannedTargets[currentVuln.Target]

		_, exist := compared.ScannedVulnerabilities[currentVuln.ID]

		if !matched && !exist {
			if currentVuln.Severity == "critical" {
				newFound.Critical++
				counts[0]++
			} else if currentVuln.Severity == "high" {
				newFound.High++
				counts[1]++
			} else if currentVuln.Severity == "medium" {
				newFound.Medium++
				counts[2]++
			} else if currentVuln.Severity == "low" {
				newFound.Low++
				counts[3]++
			} else if currentVuln.Severity == "unknown" {
				newFound.Unknown++
				counts[4]++
			}
		}
		s.ScannedTargets[currentVuln.Target] = counts
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

func (s *TrivyScanner) getShortVulnerabilities() []prototypes.ShortTrivyVulnerability {
	var vulns []prototypes.ShortTrivyVulnerability

	for _, res := range s.Trivy.Results {
		for _, vuln := range res.Vulnerabilities {
			vulnID := getVulnerabilityID(res.Target, vuln.VulnerabilityID)

			_, ok := s.ScannedVulnerabilities[vulnID]
			if ok {
				continue
			}

			s.ScannedVulnerabilities[vulnID] = struct{}{}
			vulns = append(vulns, prototypes.ShortTrivyVulnerability{
				ID:               vulnID,
				PkgName:          vuln.PkgName,
				Severity:         strings.ToLower(vuln.Severity),
				Title:            vuln.Title,
				InstalledVersion: vuln.InstalledVersion,
				FixedVersion:     vuln.FixedVersion,
			})
		}
	}

	return vulns
}

func (s *TrivyScanner) getSummary() string {
	// build summary
	stringBuilder := ""
	if len(s.Trivy.Results) > 0 {
		stringBuilder = fmt.Sprintf("Tested %d targets for known issues.", len(s.Trivy.Results))

		for target, counts := range s.ScannedTargets {
			targetBuilder := fmt.Sprintf("%s:", target)
			if counts[0] > 0 {
				targetBuilder = fmt.Sprintf("%s Critical:%d", targetBuilder, counts[0])
			}
			if counts[1] > 0 {
				targetBuilder = fmt.Sprintf("%s High:%d", targetBuilder, counts[1])
			}
			if counts[2] > 0 {
				targetBuilder = fmt.Sprintf("%s Medium:%d", targetBuilder, counts[2])
			}
			if counts[3] > 0 {
				targetBuilder = fmt.Sprintf("%s Low:%d", targetBuilder, counts[3])
			}
			if counts[4] > 0 {
				targetBuilder = fmt.Sprintf("%s Unknown:%d", targetBuilder, counts[4])
			}

			stringBuilder = fmt.Sprintf("%s %s", stringBuilder, targetBuilder)
		}
	}

	return stringBuilder
}

func (s *TrivyScanner) Export(outputType string) error {
	trivyTmpl := prototypes.TrivyTemplate{
		Name: s.Trivy.ArtifactName,
		Type: s.Trivy.ArtifactType,
	}

	var results []prototypes.ShortTrivyResult

	for _, res := range s.Trivy.Results {
		var result prototypes.ShortTrivyResult
		result.Target = res.Target
		result.Type = res.Type
		var vulns []prototypes.ShortTrivyVulnerability
		for _, vuln := range res.Vulnerabilities {
			vulnID := getVulnerabilityID(res.Target, vuln.VulnerabilityID)

			_, ok := s.ScannedVulnerabilities[vulnID]
			if ok {
				continue
			}

			s.ScannedVulnerabilities[vulnID] = struct{}{}

			severity := strings.ToLower(vuln.Severity)
			if severity == "critical" {
				result.Critical++
			} else if severity == "high" {
				result.High++
			} else if severity == "medium" {
				result.Medium++
			} else if severity == "low" {
				result.Low++
			} else if severity == "unknown" {
				result.Unknown++
			}

			vulns = append(vulns, prototypes.ShortTrivyVulnerability{
				ID:               vulnID,
				PkgName:          vuln.PkgName,
				Severity:         severity,
				Title:            vuln.Title,
				InstalledVersion: vuln.InstalledVersion,
				FixedVersion:     vuln.FixedVersion,
			})
		}

		result.Vulnerabilities = vulns
		results = append(results, result)
	}
	trivyTmpl.Results = results

	name := fmt.Sprintf("scan-report-%s-%d.html", trivyTmpl.Name, time.Now().Unix())
	name = strings.ReplaceAll(name, "/", "-")
	f, err := os.OpenFile("./output/"+name, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	switch outputType {
	case "table":
		tmpl, err := template.ParseFiles("templates/" + templates.TRIVY_SUMMARY_HTML_TABLE)
		if err != nil {
			return err
		}

		err = tmpl.Execute(f, &trivyTmpl)
		if err != nil {
			return err
		}

	case "list":

	}

	return nil
}

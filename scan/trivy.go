package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/oscarzhou/scan-report/models"
	"github.com/oscarzhou/scan-report/templates"
)

type TrivyScanner struct {
	Trivy                  models.Trivy
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

			result.SeverityStat.Count(severity)
			if vuln.FixedVersion != "" {
				result.FixableSeverityStat.Count(severity)

			}
		}

		counts[0] = result.SeverityStat.Critical
		counts[1] = result.SeverityStat.High
		counts[2] = result.SeverityStat.Medium
		counts[3] = result.SeverityStat.Low
		counts[4] = result.SeverityStat.Unknown

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
			if baseVuln.CompositeID == currentVuln.CompositeID {
				matched = true
				break
			}
		}

		if !matched {
			fixed.SeverityStat.Count(baseVuln.Severity)

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
			if baseVuln.CompositeID == currentVuln.CompositeID {
				matched = true
				break
			}
		}

		_, ok := s.ScannedTargets[currentVuln.Target]
		if !ok {
			s.ScannedTargets[currentVuln.Target] = [5]int64{0, 0, 0, 0, 0}
		}
		counts := s.ScannedTargets[currentVuln.Target]

		_, exist := compared.ScannedVulnerabilities[currentVuln.CompositeID]

		if !matched && !exist {
			newFound.SeverityStat.Count(currentVuln.Severity)

		}
		counts[0] = newFound.SeverityStat.Critical
		counts[1] = newFound.SeverityStat.High
		counts[2] = newFound.SeverityStat.Medium
		counts[3] = newFound.SeverityStat.Low
		counts[4] = newFound.SeverityStat.Unknown
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

func (s *TrivyScanner) getShortVulnerabilities() []models.ShortTrivyVulnerability {
	var vulns []models.ShortTrivyVulnerability

	for _, res := range s.Trivy.Results {
		for _, vuln := range res.Vulnerabilities {
			vulnID := getVulnerabilityID(res.Target, vuln.VulnerabilityID)

			_, ok := s.ScannedVulnerabilities[vulnID]
			if ok {
				continue
			}

			s.ScannedVulnerabilities[vulnID] = struct{}{}
			vulns = append(vulns, models.ShortTrivyVulnerability{
				ID:               vuln.VulnerabilityID,
				Target:           res.Target,
				Type:             res.Type,
				PkgName:          vuln.PkgName,
				Severity:         strings.ToLower(vuln.Severity),
				Title:            vuln.Title,
				InstalledVersion: vuln.InstalledVersion,
				FixedVersion:     vuln.FixedVersion,
				CompositeID:      vulnID,
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

func (s *TrivyScanner) getSummaryTemplate() (models.TrivySummaryTemplate, error) {
	trivyTmpl := models.TrivySummaryTemplate{
		Name: s.Trivy.ArtifactName,
		Type: s.Trivy.ArtifactType,
	}

	var results []models.ShortTrivyResult

	for _, res := range s.Trivy.Results {
		var result models.ShortTrivyResult
		result.Target = res.Target
		result.Type = res.Type
		var vulns []models.ShortTrivyVulnerability
		for _, vuln := range res.Vulnerabilities {
			vulnID := getVulnerabilityID(res.Target, vuln.VulnerabilityID)

			_, ok := s.ScannedVulnerabilities[vulnID]
			if ok {
				continue
			}

			s.ScannedVulnerabilities[vulnID] = struct{}{}

			severity := strings.ToLower(vuln.Severity)
			result.SeverityStat.Count(strings.ToLower(vuln.Severity))

			vulns = append(vulns, models.ShortTrivyVulnerability{
				ID:               vuln.VulnerabilityID,
				PkgName:          vuln.PkgName,
				Severity:         severity,
				Title:            vuln.Title,
				InstalledVersion: vuln.InstalledVersion,
				FixedVersion:     vuln.FixedVersion,
			})
		}

		result.Total = result.SeverityStat.Total()
		result.Vulnerabilities = vulns
		results = append(results, result)
	}
	trivyTmpl.Results = results
	return trivyTmpl, nil
}

func (s *TrivyScanner) Export(outputType, filename string) error {

	trivyTmpl, err := s.getSummaryTemplate()
	if err != nil {
		return err
	}

	name := filename
	if filename == "" {
		name = fmt.Sprintf("scan-report-%s-%d.html", trivyTmpl.Name, time.Now().Unix())
		name = strings.ReplaceAll(name, "/", "-")
	} else {
		if !strings.HasSuffix(name, ".html") {
			name = fmt.Sprintf("%s.html", name)
		}
	}

	f, err := os.OpenFile("./"+name, os.O_RDWR|os.O_CREATE, 0644)
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

func (s *TrivyScanner) ExportDiff(base Scanner, outputType, filename string) error {
	var trivyTmpl models.TrivyDiffTemplate

	// get short vulnerabilities of base scanner
	compared, ok := base.(*TrivyScanner)
	if !ok {
		return errors.New("assert Trivy error")
	}
	baseSummary, err := compared.getSummaryTemplate()
	if err != nil {
		return err
	}

	if baseSummary.Name == "" || baseSummary.Type == "" {
		baseSummary.Name = s.Trivy.ArtifactName
		baseSummary.Type = s.Trivy.ArtifactType
	}
	trivyTmpl.BaseSummary = baseSummary

	baseVulns := compared.getShortVulnerabilities()

	// get short vulnerabilities of current scanner
	vulns := s.getShortVulnerabilities()

	fixedSummary := models.TrivySummaryTemplate{}

	// scan the fixed vulnerabilities
	fixedResults := make(map[string]models.ShortTrivyResult)
	for _, baseVuln := range baseVulns {
		matched := false
		for _, currentVuln := range vulns {
			if baseVuln.CompositeID == currentVuln.CompositeID {
				matched = true
				break
			}
		}

		if !matched {
			result, ok := fixedResults[baseVuln.Target]
			if ok {
				result.Vulnerabilities = append(result.Vulnerabilities, baseVuln)
			} else {
				result = models.ShortTrivyResult{
					Target:          baseVuln.Target,
					Type:            baseVuln.Type,
					Vulnerabilities: []models.ShortTrivyVulnerability{baseVuln},
				}
			}

			result.SeverityStat.Count(baseVuln.Severity)

			result.Total = result.SeverityStat.Total()
			fixedResults[baseVuln.Target] = result
		}
	}

	for _, result := range fixedResults {
		fixedSummary.Results = append(fixedSummary.Results, result)
	}
	trivyTmpl.FixedSummary = fixedSummary

	newFoundSummary := models.TrivySummaryTemplate{}

	// scan the new vulnerabilities
	newFoundResults := make(map[string]models.ShortTrivyResult)
	for _, currentVuln := range vulns {
		matched := false
		for _, baseVuln := range baseVulns {
			if baseVuln.CompositeID == currentVuln.CompositeID {
				matched = true
				break
			}
		}

		_, exist := compared.ScannedVulnerabilities[currentVuln.CompositeID]

		if !matched && !exist {
			result, ok := newFoundResults[currentVuln.Target]
			if ok {
				result.Vulnerabilities = append(result.Vulnerabilities, currentVuln)
			} else {
				result = models.ShortTrivyResult{
					Target:          currentVuln.Target,
					Type:            currentVuln.Type,
					Vulnerabilities: []models.ShortTrivyVulnerability{currentVuln},
				}
			}

			result.SeverityStat.Count(currentVuln.Severity)
			result.Total = result.SeverityStat.Total()

			newFoundResults[currentVuln.Target] = result
		}
	}

	for _, result := range newFoundResults {
		newFoundSummary.Results = append(newFoundSummary.Results, result)
	}
	trivyTmpl.NewFoundSummary = newFoundSummary

	name := filename
	if filename == "" {
		name = fmt.Sprintf("scan-report-%s-%d.html", trivyTmpl.BaseSummary.Name, time.Now().Unix())
		name = strings.ReplaceAll(name, "/", "-")
	} else {
		if !strings.HasSuffix(name, ".html") {
			name = fmt.Sprintf("%s.html", name)
		}
	}

	f, err := os.OpenFile("./"+name, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	switch outputType {
	case "table":
		tmpl, err := template.ParseFiles("templates/" + templates.TRIVY_DIFF_HTML_TABLE)
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

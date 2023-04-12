package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/oscarzhou/code-security-report/models"
	"github.com/oscarzhou/code-security-report/templates"
)

var (
	ErrNullFile = errors.New("empty file")
)

type SnykScanner struct {
	Snyk models.Snyk
	// Record the scanned vulnerabilities
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
		if string(dat) == "null" {
			return snyk, ErrNullFile
		}
		return snyk, err
	}
	return snyk, nil
}

func (s *SnykScanner) Scan() (SumResult, error) {
	var result SumResult
	langs := make(map[string]struct{})

	// scan vulnerabilities
	for _, vuln := range s.Snyk.Vulnerabilities {
		_, ok := s.ScannedVulnerabilities[vuln.ID]
		if ok {
			// If the vulnerability has been scanned, skip it
			continue
		}

		s.ScannedVulnerabilities[vuln.ID] = struct{}{}

		langs[vuln.Language] = struct{}{}

		result.SeverityStat.Count(vuln.Severity)
		if vuln.IsPatchable || vuln.IsUpgradable {
			result.FixableSeverityStat.Count(vuln.Severity)
		}
	}
	result.GetTotal()
	result.ScannedObjects = s.Snyk.DependencyCount

	if result.Total > 0 {
		// If there are vulnerabilities, the result status is failure
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
		fixed    SumResult
		newFound SumResult
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
			if baseVuln.ID == currentVuln.ID {
				matched = true
				break
			}
		}

		_, exist := compared.ScannedVulnerabilities[currentVuln.ID]

		if !matched && !exist {
			newFound.SeverityStat.Count(currentVuln.Severity)
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

func (s *SnykScanner) getShortVulnerabilities() []models.ShortSnykVulnerability {
	var vulns []models.ShortSnykVulnerability
	for _, v := range s.Snyk.Vulnerabilities {
		_, ok := s.ScannedVulnerabilities[v.ID]
		if ok {
			continue
		}

		s.ScannedVulnerabilities[v.ID] = struct{}{}
		vulns = append(vulns, models.ShortSnykVulnerability{
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
		stringBuilder = fmt.Sprintf("Tested %d dependencies for known issues.\n", s.Snyk.DependencyCount)
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

	snykTmpl := models.SnykSummaryTemplate{
		Name:            s.Snyk.ProjectName,
		Languages:       result.Languages,
		Vulnerabilities: vulns,
		SeverityStat:    result.SeverityStat,
		Total:           result.SeverityStat.Total(),
	}

	name := filename
	if filename == "" {
		name = fmt.Sprintf("code-security-report-%s-%d.html", snykTmpl.Name, time.Now().Unix())
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

func (s *SnykScanner) ExportDiff(base Scanner, outputType, filename string) error {
	var snykTmpl models.SnykDiffTemplate
	// get base result
	baseResult, err := base.Scan()
	if err != nil {
		return err
	}

	// get short vulnerabilities of base scanner
	compared, ok := base.(*SnykScanner)
	if !ok {
		return errors.New("assert Snyk error")
	}

	compared.ClearCache()
	baseVulns := compared.getShortVulnerabilities()

	baseSummary := models.SnykSummaryTemplate{
		Name:            compared.Snyk.ProjectName,
		Languages:       baseResult.Languages,
		Vulnerabilities: baseVulns,
		SeverityStat:    baseResult.SeverityStat,
		Total:           baseResult.SeverityStat.Total(),
	}

	if baseSummary.Name == "" || len(baseSummary.Languages) == 0 {
		baseSummary.Name = s.Snyk.ProjectName
		langs := make(map[string]struct{})
		for _, vuln := range s.Snyk.Vulnerabilities {
			langs[vuln.Language] = struct{}{}
		}

		for lang := range langs {
			baseSummary.Languages = append(baseSummary.Languages, lang)
		}
	}
	snykTmpl.BaseSummary = baseSummary

	// get short vulnerabilities of current scanner
	vulns := s.getShortVulnerabilities()

	fixedSummary := models.SnykSummaryTemplate{}
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
			fixedSummary.Vulnerabilities = append(fixedSummary.Vulnerabilities, baseVuln)
			fixedSummary.SeverityStat.Count(baseVuln.Severity)

		}
	}

	fixedSummary.Total = fixedSummary.SeverityStat.Total()
	snykTmpl.FixedSummary = fixedSummary

	newFoundSummary := models.SnykSummaryTemplate{}
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
			newFoundSummary.Vulnerabilities = append(newFoundSummary.Vulnerabilities, currentVuln)
			newFoundSummary.SeverityStat.Count(currentVuln.Severity)

		}
	}
	newFoundSummary.Total = fixedSummary.SeverityStat.Total()

	snykTmpl.NewFoundSummary = newFoundSummary

	name := filename
	if filename == "" {
		name = fmt.Sprintf("code-security-report-%s-%d.html", snykTmpl.BaseSummary.Name, time.Now().Unix())
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

	funcs := template.FuncMap{"join": strings.Join}
	switch outputType {
	case "table":
		tmpl, err := template.New(templates.SNYK_DIFF_HTML_TABLE).Funcs(funcs).ParseFiles("templates/" + templates.SNYK_DIFF_HTML_TABLE)
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

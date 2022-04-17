package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/oscarzhou/scan-report/prototypes"
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

	for _, v := range s.Snyk.Vulnerabilities {
		_, ok := s.ScannedVulnerabilities[v.ID]
		if ok {
			continue
		}

		s.ScannedVulnerabilities[v.ID] = struct{}{}

		if v.Severity == "critical" {
			result.Critical++
		} else if v.Severity == "high" {
			result.High++
		} else if v.Severity == "medium" {
			result.Medium++
		} else if v.Severity == "low" {
			result.Low++
		} else if v.Severity == "unknown" {
			result.Unknown++
		}

		if v.IsPatchable || v.IsUpgradable {
			if v.Severity == "critical" {
				result.FixableCritical++
			} else if v.Severity == "high" {
				result.FixableHigh++
			} else if v.Severity == "medium" {
				result.FixableMedium++
			} else if v.Severity == "low" {
				result.FixableLow++
			} else if v.Severity == "unknown" {
				result.FixableUnknown++
			}
		}
	}
	result.GetTotal()
	result.ScannedObjects = s.Snyk.DependencyCount
	if result.Total > 0 {
		result.Status = "failure"
	} else {
		result.Status = "success"
	}

	result.Summarize()

	return result, nil
}

type shortVulnearibility struct {
	ID         string
	ModuleName string
	Severity   string
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
	fixed.Summarize()
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

		if !matched {
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
	newFound.Summarize()
	result.NewFound = newFound

	if result.NewFound.Total == 0 {
		result.Status = "success"
	} else {
		result.Status = "failure"
	}

	result.Summarize()
	return result, nil
}

func (s *SnykScanner) getShortVulnerabilities() []shortVulnearibility {
	var vulns []shortVulnearibility
	for _, v := range s.Snyk.Vulnerabilities {
		_, ok := s.ScannedVulnerabilities[v.ID]
		if ok {
			continue
		}

		s.ScannedVulnerabilities[v.ID] = struct{}{}
		vulns = append(vulns, shortVulnearibility{
			ID:         v.ID,
			ModuleName: v.ModuleName,
			Severity:   v.Severity,
		})

	}
	return vulns
}

package scan

import (
	"encoding/json"

	"github.com/oscarzhou/scan-report/prototypes"
)

type SnykScanner struct {
	prototypes.Snyk
	scannedVulnerabilities map[string]struct{}
}

func (s *SnykScanner) Scan(in []byte) (Result, error) {
	var result Result
	err := json.Unmarshal(in, s)
	if err != nil {
		return result, err
	}

	s.scannedVulnerabilities = make(map[string]struct{})

	for _, v := range s.Vulnerabilities {
		_, ok := s.scannedVulnerabilities[v.ID]
		if ok {
			continue
		}

		s.scannedVulnerabilities[v.ID] = struct{}{}

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

	result.ScannedObjects = s.DependencyCount

	if result.Critical+result.High > 0 {
		result.Status = "failure"
	} else {
		result.Status = "success"
	}

	return result, nil
}

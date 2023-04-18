package models

import "fmt"

type SeverityStat struct {
	Critical int64 `json:"critical"`
	High     int64 `json:"high"`
	Medium   int64 `json:"medium"`
	Low      int64 `json:"low"`
	Unknown  int64 `json:"unknown"`
}

func (ss *SeverityStat) Count(severity string) {
	if severity == SEVERITY_LEVEL_CRITICAL {
		ss.Critical++
	} else if severity == SEVERITY_LEVEL_HIGH {
		ss.High++
	} else if severity == SEVERITY_LEVEL_MEDIUM {
		ss.Medium++
	} else if severity == SEVERITY_LEVEL_LOW {
		ss.Low++
	} else if severity == SEVERITY_LEVEL_UNKNOWN {
		ss.Unknown++
	}
}

func (ss *SeverityStat) Total() int64 {
	return ss.Critical + ss.High + ss.Medium + ss.Low + ss.Unknown
}

func (ss *SeverityStat) Summarize() string {
	stringBuilder := fmt.Sprintf("Severity Statistic: ")
	if ss.Critical > 0 {
		stringBuilder = fmt.Sprintf("%sCritical:%d ", stringBuilder, ss.Critical)
	}
	if ss.High > 0 {
		stringBuilder = fmt.Sprintf("%sHigh:%d ", stringBuilder, ss.High)
	}
	if ss.Medium > 0 {
		stringBuilder = fmt.Sprintf("%sMedium:%d ", stringBuilder, ss.Medium)
	}
	if ss.Low > 0 {
		stringBuilder = fmt.Sprintf("%sLow:%d ", stringBuilder, ss.Low)
	}
	if ss.Unknown > 0 {
		stringBuilder = fmt.Sprintf("%sUnknown:%d ", stringBuilder, ss.Unknown)
	}
	if ss.Total() == 0 {
		stringBuilder = fmt.Sprintf("%sNothing found", stringBuilder)
	}
	return stringBuilder
}

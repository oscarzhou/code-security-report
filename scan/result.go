package scan

import (
	"encoding/json"
	"fmt"
)

const (
	RESULT_SUCCESS string = "success"
	RESULT_FAILURE string = "failure"
)

type Result struct {
	ScannedObjects  int64 `json:",omitempty;scannedObjects"`
	Critical        int64 `json:"critical"`
	High            int64 `json:"high"`
	Medium          int64 `json:"medium"`
	Low             int64 `json:"low"`
	Unknown         int64 `json:"unknown"`
	Total           int64 `json:"total"`
	FixableCritical int64
	FixableHigh     int64
	FixableMedium   int64
	FixableLow      int64
	FixableUnknown  int64
	Languages       []string
	Summary         string `json:"summary"`
	Status          string `json:"status"`
}

func (r *Result) GetTotal() {
	r.Total = r.Critical + r.High + r.Medium + r.Low + r.Unknown
}

func (r *Result) SetSummary() {
	r.Summary = GetCommonSummary(r)
}

func GetCommonSummary(r *Result) string {
	// build summary
	stringBuilder := fmt.Sprintf("%s Total:", r.Summary)
	if r.Critical > 0 {
		stringBuilder = fmt.Sprintf("%s Critical:%d", stringBuilder, r.Critical)
	}
	if r.High > 0 {
		stringBuilder = fmt.Sprintf("%s High:%d", stringBuilder, r.High)
	}
	if r.Medium > 0 {
		stringBuilder = fmt.Sprintf("%s Medium:%d", stringBuilder, r.Medium)
	}
	if r.Low > 0 {
		stringBuilder = fmt.Sprintf("%s Low:%d", stringBuilder, r.Low)
	}
	if r.Unknown > 0 {
		stringBuilder = fmt.Sprintf("%s Unknown:%d", stringBuilder, r.Unknown)
	}
	if r.Total == 0 {
		stringBuilder = fmt.Sprintf("%s Nothing found", stringBuilder)
	}
	return stringBuilder
}

func (r *Result) Output(outputType string) {
	if outputType == "matrix" {
		results := []Result{*r}

		ret, err := json.Marshal(results)
		if err != nil {
			fmt.Println(err.Error())
		}

		fmt.Println(string(ret))
		return
	}

	ret, err := json.Marshal(r)
	if err != nil {
		fmt.Println(err.Error())
	}

	fmt.Println(string(ret))
}

type DiffResult struct {
	Base     Result
	Fixed    Result
	NewFound Result
	Summary  string
	Status   string
}

func (r *DiffResult) Summarize() {
	r.Summary = fmt.Sprintf("Base summary:%s, Fixed summary:%s, New found summary:%s.", r.Base.Summary, r.Fixed.Summary, r.NewFound.Summary)
}

func (r *DiffResult) Output(outputType string) {
	if outputType == "matrix" {
		results := []DiffResult{*r}

		ret, err := json.Marshal(results)
		if err != nil {
			fmt.Println(err.Error())
		}

		fmt.Println(string(ret))
		return
	}

	ret, err := json.Marshal(r)
	if err != nil {
		fmt.Println(err.Error())
	}

	fmt.Println(string(ret))
}

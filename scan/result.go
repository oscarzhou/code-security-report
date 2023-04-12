package scan

import (
	"encoding/json"
	"fmt"

	"github.com/oscarzhou/scan-report/models"
)

const (
	RESULT_SUCCESS string = "success"
	RESULT_FAILURE string = "failure"
)

type Result struct {
	ScannedObjects      int64 `json:",omitempty;scannedObjects"`
	SeverityStat        models.SeverityStat
	Total               int64 `json:"total"`
	FixableSeverityStat models.SeverityStat
	Languages           []string
	Summary             string `json:"summary"`
	Status              string `json:"status"`
}

func (r *Result) GetTotal() {
	r.Total = r.SeverityStat.Total()
}

func (r *Result) SetSummary() {
	r.Summary = GetCommonSummary(r)
}

func GetCommonSummary(r *Result) string {
	return r.SeverityStat.Summarize()
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

package scan

import (
	"encoding/json"
	"fmt"
)

type DiffResult struct {
	Base     SumResult
	Fixed    SumResult
	NewFound SumResult
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

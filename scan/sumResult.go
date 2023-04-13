package scan

import (
	"encoding/json"
	"fmt"

	"github.com/oscarzhou/code-security-report/models"
)

const (
	RESULT_SUCCESS string = "success"
	RESULT_FAILURE string = "failure"
)

type SumResult struct {
	ScannedObjects      int64 `json:",omitempty;scannedObjects"`
	SeverityStat        models.SeverityStat
	Total               int64 `json:"total"`
	FixableSeverityStat models.SeverityStat
	Languages           []string
	Summary             string `json:"summary"`
	Status              string `json:"status"`
}

func (r *SumResult) Output(outputType string) {
	if outputType == "matrix" {
		results := []SumResult{*r}

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

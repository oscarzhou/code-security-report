package scan

import (
	"encoding/json"
	"fmt"
)

type Result struct {
	ScannedObjects  int64 `json:"scannedObjects"`
	Critical        int64 `json:"critical"`
	High            int64 `json:"high"`
	Medium          int64 `json:"medium"`
	Low             int64 `json:"low"`
	Unknown         int64 `json:"unknown"`
	FixableCritical int64
	FixableHigh     int64
	FixableMedium   int64
	FixableLow      int64
	FixableUnknown  int64
	Summary         string `json:"summary"`
	Status          string `json:"status"`
}

func (r *Result) Summarize() {
	stringBuilder := fmt.Sprintf("Tested %d dependencies for known issues\n%d critical, %d high, %d medium, %d low, %d unknown", r.ScannedObjects, r.Critical, r.High, r.Medium, r.Low, r.Unknown)

	r.Summary = stringBuilder

	ret, err := json.Marshal(r)
	if err != nil {
		fmt.Println(err.Error())
	}

	fmt.Println(string(ret))
}

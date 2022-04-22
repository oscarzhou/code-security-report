package scan

type Scanner interface {
	Scan() (Result, error)
	Diff(base Scanner) (DiffResult, error)
	Export(outputType string) error
}

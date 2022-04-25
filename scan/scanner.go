package scan

type Scanner interface {
	Scan() (Result, error)
	Diff(base Scanner) (DiffResult, error)
	Export(outputType, filename string) error
	ExportDiff(base Scanner, outputType, filename string) error
}

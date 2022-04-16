package scan

type Scanner interface {
	Scan() (Result, error)
}

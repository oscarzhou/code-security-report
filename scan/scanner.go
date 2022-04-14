package scan

type Scanner interface {
	Scan(in []byte) (Result, error)
}

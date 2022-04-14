set -x

mkdir -p binary

# the go get adds 8 seconds
go get -t -d -v ./...

# the build takes 2 seconds
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
	--installsuffix cgo \
	--ldflags '-s' \
	-o "binary/scanreport" \
	.

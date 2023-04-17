
set -x

function build_binary() {
	mkdir -p binary

	# the go get adds 8 seconds
	go get -t -d -v ./...

	# the build takes 2 seconds
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
		--installsuffix cgo \
		--ldflags '-s' \
		-o "binary/scanreport" \
		.
}

function build_docker() {
	printf "Input image tag\n"
	read -p "major: " MAJOR
	read -p "minor: " MINOR
	read -p "patch: " PATCH

	semver=${MAJOR}.${MINOR}.${PATCH}
	build_binary
	docker build -t oscarzhou/code-security-report:${semver} -t oscarzhou/code-security-report:latest -f Dockerfile .
}


function push_image() {
	printf "Input image tag\n"
	read -p "major: " MAJOR
	read -p "minor: " MINOR
	read -p "patch: " PATCH

	semver=${MAJOR}.${MINOR}.${PATCH}
	docker image push oscarzhou/code-security-report:${semver}
}

function main() {
	if [[ "$1" == "build_binary" ]]; then
		build_binary
	elif [[ "$1" == "build_docker" ]]; then 
		build_docker
	elif [[ "$1" == "push_image" ]]; then 
		push_image
	fi
}

main "$@"
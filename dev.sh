#!/bin/bash

function bump_version() {
    CURRENT_VERSION=$(grep -o '[0-9]*\.[0-9]*\.[0-9]*' ./cmd/versionCmd.go)
    printf "Current image tag: "
    echo $CURRENT_VERSION

	printf "Set up version\n"
	read -p "major: " MAJOR
	read -p "minor: " MINOR
	read -p "patch: " PATCH

	semver=${MAJOR}.${MINOR}.${PATCH}

    # Update version
    sed -i "s/$CURRENT_VERSION/$semver/g" ./cmd/versionCmd.go

    git add ./cmd/versionCmd.go
    echo commit message: "build: bump version to $semver"
}

function main() {
	if [[ "$1" == "bump_version" ]]; then
		bump_version
	fi
}

main "$@"
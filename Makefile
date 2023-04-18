# See: https://gist.github.com/asukakenji/f15ba7e588ac42795f421b48b8aede63
# For a list of valid GOOS and GOARCH values
# Note: these can be overriden on the command line e.g. `make PLATFORM=<platform> ARCH=<arch>`
PLATFORM=$(shell go env GOOS)
ARCH=$(shell go env GOARCH)

ifeq ("$(PLATFORM)", "windows")
bin=code-security-report.exe
else
bin=code-security-report
endif

dist := dist
image := oscarzhou/code-security-report:latest
.PHONY: binary build image clean 

binary:
	@echo "Building code security report binary for $(PLATFORM)/$(ARCH)..."
	GOOS="$(PLATFORM)" GOARCH="$(ARCH)" CGO_ENABLED=0 go build -a --installsuffix cgo --ldflags '-s' -o dist/$(bin)

build: binary 
	@echo "done."

image: build
	docker build -f build/$(PLATFORM)/Dockerfile -t $(image) .

clean:
	rm -rf $(dist)
	rm -rf .tmp
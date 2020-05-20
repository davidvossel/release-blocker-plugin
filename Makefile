
.PHONY: all deps-update build
all: build

build:
	go build cmd/release-blocker/release-blocker.go

deps-update:
	GO111MODULE=on; go mod tidy
	GO111MODULE=on; go mod vendor

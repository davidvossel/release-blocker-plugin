
.PHONY: all deps-update
all: deps-update

build:
	go build cmd/release-blocker/release-blocker.go

deps-update:
	go mod tidy
	go mod vendor

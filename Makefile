MODULE  := github.com/SBKubric/3ax-ui-monitoring
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X $(MODULE)/internal/config.version=$(VERSION)

.PHONY: build test vet fmt lint check

build:
	go build -ldflags "$(LDFLAGS)" -o mon-server ./cmd/mon-server

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

fmt:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needs to be run on:"; gofmt -l .; exit 1)

lint:
	staticcheck ./...

check: fmt vet lint test

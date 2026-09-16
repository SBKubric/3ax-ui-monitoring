# mon-server developer entry points. See docs/agents/testing.md for the policy
# these targets implement.

GO ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE ?= 3ax-mon-server:$(VERSION)

.PHONY: all build fmt vet test test-race e2e image clean

all: build

## build: compile the mon-server binary into ./mon-server
build:
	CGO_ENABLED=1 $(GO) build -trimpath -ldflags "-X main.version=$(VERSION)" -o mon-server ./cmd/mon-server

## fmt: format every Go file in the module
fmt:
	gofmt -w $(shell find . -name '*.go' -not -path './.git/*')

## vet: run go vet over the module
vet:
	$(GO) vet ./...

## test: unit tests, the quick loop
test:
	$(GO) test -count=1 ./...

## test-race: the CI command from docs/agents/testing.md
test-race:
	$(GO) test -race -count=1 ./...

## image: build the Docker image the e2e suite runs against
image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

## e2e: build the image, bring compose up, run Playwright, tear down
e2e: image
	$(MAKE) -C e2e run IMAGE=$(IMAGE)

clean:
	rm -f mon-server
	rm -rf e2e/test-results e2e/playwright-report

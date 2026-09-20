MODULE  := github.com/SBKubric/3ax-ui-monitoring
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X $(MODULE)/internal/config.version=$(VERSION) -X $(MODULE)/internal/version.version=$(VERSION)

.PHONY: build build-client test vet fmt lint check e2e docker-client

build:
	go build -ldflags "$(LDFLAGS)" -o mon-server ./cmd/mon-server

build-client:
	go build -ldflags "$(LDFLAGS)" -o mon-client ./cmd/mon-client

## docker-client — builds the mon-client stand image (Dockerfile.mon-client,
## issue #23). Not packaging (that is SBKubric/3ax-ui-proxy#39) — just
## enough to run one container by hand on a test stand; see
## docs/runbooks/mon-client-stand.md.
docker-client:
	docker build -f Dockerfile.mon-client -t mon-client:dev .

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

fmt:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needs to be run on:"; gofmt -l .; exit 1)

lint:
	staticcheck ./...

check: fmt vet lint test

## e2e — Playwright harness against this repo's own Docker image
## (docs/agents/testing.md, "E2E tests"). Builds the image, starts mon-server
## from e2e/docker-compose.yml with a fresh database, installs the e2e/
## Node toolchain and Chromium, runs the specs, and always tears the stack
## (and its database volume) down — even when the tests fail — while
## preserving the tests' exit code.
##
## Browser install tries `--with-deps` first (apt-get's Chromium system
## libraries as root — what CI, e.g. GitHub Actions ubuntu-latest, has) and
## falls back to a plain browser-only install if that fails, which is what
## a host with no passwordless sudo needs when those libraries are already
## present.
e2e:
	set -e; \
	trap 'docker compose -f e2e/docker-compose.yml down -v' EXIT; \
	docker compose -f e2e/docker-compose.yml up --build --wait -d; \
	( cd e2e && npm ci && (npx playwright install --with-deps chromium || npx playwright install chromium) && npx playwright test )

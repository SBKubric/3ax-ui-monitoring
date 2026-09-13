# Testing policy

Applies to every change in this repository. The same policy lives in each 3AX-UI repo (`3ax-ui-proxy`, `3ax-ui-monitoring`, `3ax-ui-orchestrator`); the panel repo is the source of truth, copy changes to the others.

## The rule

- **Legacy code** (inherited from upstream, or fork code written before this policy) stays as it is: no retroactive coverage.
- **A fix in legacy code ships with a unit test that reproduces the bug**: red on the old code, green on the fix. Fixing without the test is not done.
- **New functionality** (a new feature, a new file, a new endpoint, a new page — the fork features such as tunnel subscription and monitoring included) **ships with unit tests and e2e tests**. A feature without both is not done.

Done means: the tests exist, they pass locally, and `go test -race -count=1 ./...` (the CI command) is green.

## Unit tests

- Go tests beside the code (`foo_test.go` next to `foo.go`), table-driven where cases repeat.
- HTTP handlers through `net/http/httptest`; database through SQLite in a temp file; no network, no real xray, no real Telegram — fake the boundary.
- A bug-fix test names the bug in its name (`TestSubService_HostOverrideKeepsPort`) so the regression stays legible.

## E2E tests

- Framework: `@playwright/test` (Node + TypeScript), in the `e2e/` directory with its own `package.json`. The Go build stays Node-free; Node is a test-time dependency only.
- The app under test runs from **this repository's Docker image** via `e2e/docker-compose.yml`: fresh database per run, credentials from compose environment. Tests never touch a developer's or production instance.
- Entry point: `make e2e` — builds the image, starts compose, runs `npx playwright test`, tears down. The first e2e spec in a repo lands together with this harness.
- Every new user-facing feature adds at least one spec that walks the happy path through the UI; API-only features walk it through Playwright's request context. Select elements by role or `data-testid`, never by CSS structure.
- When to run: locally before pushing a feature, and in the release workflow before a tag is published. Pull-request CI runs unit tests only.

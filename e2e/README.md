# End-to-end suite

Playwright specs driving mon-server's admin UI in a browser and its `/v1`
protocol through Playwright's request context, against a container built from
this repository's `Dockerfile`. Policy: `docs/agents/testing.md`.

```sh
make e2e          # from the repository root: build image, up, test, down
make -C e2e run   # same cycle, reusing an already built image
```

The container runs with `tls.mode = files` and a self-signed certificate
generated into `e2e/certs/` (ACME cannot reach a test container), a database on
tmpfs so every run starts empty, and an administrator seeded from
`MON_ADMIN_USER` / `MON_ADMIN_PASSWORD`.

Select elements by role or `data-testid`, never by CSS structure.

## The specs

| file | what it walks |
|---|---|
| `specs/health-login.spec.ts` | `/healthz` without credentials; the login card; a refused password; a page and an API call without a session; logging out |
| `specs/registration.spec.ts` | the whole registration walk: `POST /v1/register`, the pairing code on the Requests page, the Approve modal, the token handed out once, the new row under mon-clients |
| `specs/protocol.spec.ts` | `/v1/config`, `/v1/probe` and `/v1/heartbeat` with a real client token, and all three with a revoked one |
| `specs/settings-operations.spec.ts` | Settings saves and survives a reload; Check reports an unreachable panel and saves nothing; Revoke kills the token |
| `specs/no-target-state.spec.ts` | the rule of spec §1: the state of targets appears nowhere in the admin UI |

`support/mon.ts` holds what they share: the registration and admin API calls,
and the helpers that turn a `data-testid` into the control inside it.

Each spec sets up what it needs and depends on no other file. They run
serially, one worker, against one mon-server whose database starts empty.

## Registration is rate limited, and the suite waits for it

mon-server accepts **one registration request per minute and IP** (spec §6),
and every spec comes from the same address, so the four specs that need a
mon-client of their own cannot all register at once. `submitRegistration` in
`support/mon.ts` therefore waits out the `Retry-After` mon-server itself sends
and files the request again — the wait is the server's own answer, not a guess
about timing. That is why the per-test timeout in `playwright.config.ts` is
three minutes and a full run takes about three: roughly two of them are the
rate limit.

The alternative — one registration shared by every spec — would make the files
depend on each other's order, which is worse than a slow suite.

## A browser that is not the pinned one

`MON_CHROMIUM=/path/to/chrome npx playwright test` launches that executable
instead of the browser `@playwright/test` downloads. It exists for sandboxes
that ship a browser of their own; unset, which is what `make e2e` runs,
Playwright uses its own.

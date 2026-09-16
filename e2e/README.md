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

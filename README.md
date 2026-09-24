# mon-server

Monitoring for [3AX-UI](https://github.com/SBKubric/3ax-ui-proxy) panel inbounds: **mon-server** runs on its own box and is the single source of truth for monitoring; **mon-client** boxes in each target region probe every inbound through the proxy front and directly, once a minute; the panel only displays what mon-server tells it and sends Telegram on mon-server's behalf. Terms below follow [CONTEXT.md](CONTEXT.md). See [docs/spec/mon-server.md](docs/spec/mon-server.md) for the full spec this README summarizes, [docs/spec/mon-client.md](docs/spec/mon-client.md) for the mon-client side, [mon-protocol.md](docs/spec/mon-protocol.md) for the mon-server↔mon-client wire protocol, [the panel's monitoring contract](https://github.com/SBKubric/3ax-ui-proxy/blob/main/docs/spec/monitoring-contract.md) for what mon-server calls on the panel, and [ADR 0003](https://github.com/SBKubric/3ax-ui-proxy/blob/main/docs/adr/0003-mon-server-single-source-panel-passive.md) for why the panel is a passive receiver.

## Requirements

- A Linux box with a **public IP** it can be reached on. mon-server terminates its own TLS and needs no reverse proxy in front of it.
- **Port 443 open to the whole internet** — both Let's Encrypt's `tls-alpn-01` validators (default TLS mode, see below) and every mon-client need to reach it. No other inbound port is used.
- **NTP running.** Let's Encrypt's certificate validation and mon-server's own state machine (timestamps, timeouts, the 24h/7d retention windows) all depend on the clock being correct.
- No domain name is required: the default TLS mode gets a certificate for the box's bare IP address.

Packaging (a container image or an installer) is intentionally out of scope here — that is tracked separately in [SBKubric/3ax-ui-proxy#38](https://github.com/SBKubric/3ax-ui-proxy/issues/38). What follows is how to build and run the binary by hand or under systemd.

## Quick start

### 1. Build

```sh
make build          # -> ./mon-server, version stamped from `git describe`
```

or build a container image with the project's `Dockerfile` if you prefer that (see that file for details — it is not covered here).

Or download a release: every `v*` tag publishes `mon-server-linux-amd64.tar.gz` and `mon-client-linux-amd64.tar.gz` (each with a `.sha256`) on the [Releases](https://github.com/SBKubric/3ax-ui-monitoring/releases) page, built by `.github/workflows/release.yml`. Both binaries are static, so they run on any supported distribution (Debian 12/13, Ubuntu 22.04/24.04) regardless of its glibc. Tags with a suffix (`v0.1.0-stand.1`) are pre-releases.

```sh
TAG=v0.1.0-stand.1
curl -LO https://github.com/SBKubric/3ax-ui-monitoring/releases/download/$TAG/mon-server-linux-amd64.tar.gz
curl -LO https://github.com/SBKubric/3ax-ui-monitoring/releases/download/$TAG/mon-server-linux-amd64.tar.gz.sha256
sha256sum -c mon-server-linux-amd64.tar.gz.sha256 && tar -xzf mon-server-linux-amd64.tar.gz
```

### 2. Bootstrap config

mon-server needs a minimal bootstrap config *before* it has a database to keep settings in — everything else (panel URL, Telegram, thresholds) is configured later, at runtime, through the admin UI (see the spec's §9.4, [docs/spec/mon-server.md](docs/spec/mon-server.md)). Write `/etc/mon-server/config.json`:

```json
{
  "listen": ":443",
  "publicIp": "203.0.113.10",
  "dataDir": "/var/lib/mon-server",
  "tls": { "mode": "acme-ip" }
}
```

| key | ENV | default | meaning |
|---|---|---|---|
| `listen` | `MON_LISTEN` | `:443` | address the single HTTPS listener binds — serves `/v1/*` (mon-clients), `/admin/*` (admin UI) and `/healthz` on the same port |
| `publicIp` | `MON_PUBLIC_IP` | — | this box's public IP; required in `acme-ip` mode (Let's Encrypt needs to know what to request a certificate for) |
| `dataDir` | `MON_DATA_DIR` | `/var/lib/mon-server` | where the SQLite file and, in `acme-ip` mode, certmagic's certificate cache live |
| `tls.mode` | `MON_TLS_MODE` | `acme-ip` | `acme-ip` (built-in Let's Encrypt cert for `publicIp`, no domain needed) or `files` (bring your own cert/key — a real domain, or a test environment that must not touch the ACME network) |
| `tls.cert` | `MON_TLS_CERT` | — | certificate path, required when `tls.mode=files` |
| `tls.key` | `MON_TLS_KEY` | — | key path, required when `tls.mode=files` |

ENV always wins over the file, so a systemd unit or container can override a single field without templating the whole JSON. An unknown key in the file is a hard error (almost always a typo, or a setting that belongs in the admin UI instead).

### 3. Set the admin login

```sh
mon-server admin set alice -config /etc/mon-server/config.json
```

Prompts for the password twice on a terminal (bcrypt hash only, never stored in the clear); running it again changes the login and/or password. For scripted provisioning, set `MON_ADMIN_PASSWORD` to skip the prompt.

### 4. Run

```sh
mon-server run -config /etc/mon-server/config.json
```

Then open `https://<publicIp>/admin/`, log in, and fill in **Settings → Real server**: `panelUrl` (the panel's base URL) and `monToken` (from the panel's Monitoring tab). Use **Check** to verify those two values reach the panel before saving. While you're there, the **Telegram** tab (`tgToken`, `tgChatId`) lets mon-server send its own alerts (panel unreachable, config errors) — optional, but recommended.

### What happens next

Once the panel is reachable, mon-server polls it once a minute for inbound state and probe configs, builds each mon-client's per-target config, and starts accepting heartbeats and tunnel probes. New mon-client boxes show up under **Requests** with a pairing code to approve against the box's own boot log; approved ones then appear under **mon-clients** with their live state.

### Version

```sh
mon-server version
```

Prints the build's version string (the release tag, `make build`'s `git describe`, or `dev` for an unstamped local build).

## Running under systemd

```ini
[Unit]
Description=mon-server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/mon-server run
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
StateDirectory=mon-server
User=mon-server

[Install]
WantedBy=multi-user.target
```

`AmbientCapabilities=CAP_NET_BIND_SERVICE` lets the process bind `:443` without running as root; `StateDirectory=mon-server` gives it `/var/lib/mon-server` (matching `dataDir`'s default) owned by the service user. Adjust `dataDir`/`MON_DATA_DIR` if you point `StateDirectory` elsewhere.

## mon-client

**mon-client** is the box each target region runs: one Go process in one container, with no
capabilities, that mon-server assigns a set of targets to. For every xray-target it runs a child
`xray` process (binary from the official image, config written to a file, stderr read over a
pipe); for every AWG-target it uses an in-process `amneziawg-go`/`netstack` device — no
`/dev/net/tun`, no routes, no privileges. Once a minute it sends mon-server a tunnel probe through
each target's tunnel and one heartbeat past them. See
[docs/spec/mon-client.md](docs/spec/mon-client.md) for the full spec.

Packaging (a container image meant for production, or an installer) is out of scope here too —
tracked in [SBKubric/3ax-ui-proxy#39](https://github.com/SBKubric/3ax-ui-proxy/issues/39).
`Dockerfile.mon-client` is a stand sketch: enough to build and run one container by hand for
manual verification against a real mon-server and panel.

```sh
make docker-client   # docker build -f Dockerfile.mon-client -t mon-client:dev .

docker run -d --name mon-client \
  -v mon-client-state:/var/lib/mon-client \
  -e MON_SERVER_URL=https://<mon-server-ip>:443 \
  mon-client:dev
```

The single required parameter is `MON_SERVER_URL` (or `--server`), mon-server's own base URL —
mon-client dials it with a pairing code, prints that code to `docker logs`, and waits for an
administrator to approve the resulting request under mon-server's admin UI **Requests** page.
Everything else it needs (targets, probe accounts, config revisions) comes from mon-server itself.

State — `state.json` (registration), `cycles.json` (unverified heartbeat buffer) and `xray.json`
(generated xray config) — lives under `/var/lib/mon-client`, which the image declares as a
`VOLUME` so it survives a container restart.

For the full manual stand checklist (registration, `UP` on both paths, `DOWN` on a stopped
inbound, `reality_real_cert`, `awg_no_handshake`, buffering through a mon-server outage, `401`
after Revoke), see [docs/runbooks/mon-client-stand.md](docs/runbooks/mon-client-stand.md).

## Development

```sh
make check     # fmt + vet + staticcheck + test, the full gate CI runs
make test      # go test -race -count=1 ./...
```

An end-to-end harness (`make e2e`, driving a real panel stub end to end) is being added on this branch stack by another change; once it lands, see `e2e/` for how to run it.

There is no `go` toolchain assumption beyond what `go.mod` names — `make build`/`make test` work with a plain local Go install.

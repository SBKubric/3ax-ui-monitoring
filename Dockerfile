# ========================================================
# Stage: builder — compiles mon-server. CGO is required by
# gorm.io/driver/sqlite (mattn/go-sqlite3), so the image needs a real C
# toolchain, not just the Go compiler (architecture brief §1: "gorm +
# gorm.io/driver/sqlite (mattn, CGO)").
# ========================================================
FROM golang:1.26-bookworm AS builder
WORKDIR /src

ARG VERSION=dev

# Cache module downloads separately from the source tree so an edit to
# application code does not re-fetch the module graph.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENV CGO_ENABLED=1
RUN go build -ldflags "-X github.com/SBKubric/3ax-ui-monitoring/internal/config.version=$VERSION" \
    -o /out/mon-server ./cmd/mon-server

# ========================================================
# Stage: runtime — debian-slim, not alpine/scratch: CGO_ENABLED=1 links the
# builder's glibc, and a real cert store + tzdata are needed for the outbound
# Telegram/panel HTTPS calls (spec §9.4, §4). curl backs the e2e compose
# healthcheck (docs/agents/testing.md); openssl mints the e2e harness's
# self-signed certificate (e2e/docker-compose.yml) — a production install
# with tls.mode=acme-ip never calls it.
# ========================================================
FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       tzdata \
       curl \
       openssl \
    && rm -rf /var/lib/apt/lists/*

# Non-root: mon-server needs no special privilege beyond binding :443, which
# Docker's port publishing does on the host's behalf — the process itself
# never needs CAP_NET_BIND_SERVICE inside the container.
RUN groupadd --system mon-server \
    && useradd --system --gid mon-server --home-dir /var/lib/mon-server --shell /usr/sbin/nologin mon-server

COPY --from=builder /out/mon-server /app/mon-server

# /certs exists, empty and owned by the runtime user, only so that the e2e
# harness can mount a shared volume there (e2e/docker-compose.yml publishes
# the self-signed certificate for the mon-client container to trust): Docker
# seeds a fresh named volume from the image's directory, ownership included,
# and a root-owned mount point would be unwritable by this non-root process.
# A production install never touches it.
RUN mkdir -p /var/lib/mon-server /certs && chown -R mon-server:mon-server /var/lib/mon-server /certs /app

USER mon-server

# The SQLite database, and (tls.mode=files installs, including the e2e
# harness) the certificate keypair, live here — spec §2's dataDir default.
VOLUME ["/var/lib/mon-server"]

EXPOSE 443

ENTRYPOINT ["/app/mon-server"]
CMD ["run"]

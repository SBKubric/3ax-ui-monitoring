# mon-server image. Used in production and, per docs/agents/testing.md, as the
# app under test for the Playwright e2e suite: `make e2e` builds this image and
# runs the specs against a container with a fresh database.
#
# CGO is required: the SQLite driver is gorm.io/driver/sqlite (mattn/go-sqlite3),
# the same driver the panel uses.
FROM golang:1.26-bookworm AS build

WORKDIR /src

# Dependencies first, so a source-only change does not refetch the module graph.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=1 go build -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/mon-server ./cmd/mon-server

FROM debian:bookworm-slim

# ca-certificates: ACME and the panel are reached over HTTPS.
# tzdata: timestamps are stored in UTC, but logs read better with a real zoneinfo.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/mon-server /usr/local/bin/mon-server

ENV MON_DATA_DIR=/var/lib/mon-server \
    MON_LISTEN=:443
VOLUME ["/var/lib/mon-server"]
EXPOSE 443

ENTRYPOINT ["/usr/local/bin/mon-server"]
CMD ["run"]

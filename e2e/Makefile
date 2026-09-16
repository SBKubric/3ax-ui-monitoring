# Entry point used by the repository root `make e2e`.
MON_PORT ?= 8443
MON_ADMIN_USER ?= admin
MON_ADMIN_PASSWORD ?= e2e-password
IMAGE ?= 3ax-mon-server:dev
COMPOSE ?= docker compose
WAIT_SECONDS ?= 90

export MON_IMAGE = $(IMAGE)
export MON_PORT
export MON_ADMIN_USER
export MON_ADMIN_PASSWORD

.PHONY: run certs up wait test down install

## run: the whole cycle — certificates, compose up, Playwright, tear down
run: certs install up
	@$(MAKE) wait || { $(COMPOSE) logs mon-server; $(MAKE) down; exit 1; }
	@$(MAKE) test; status=$$?; $(MAKE) down; exit $$status

## certs: a self-signed certificate for the container's files TLS mode
certs:
	@mkdir -p certs
	@test -f certs/server.crt || openssl req -x509 -newkey rsa:2048 -nodes \
		-keyout certs/server.key -out certs/server.crt -days 365 \
		-subj "/CN=localhost" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
	@chmod 644 certs/server.key

install:
	@test -d node_modules || npm ci --no-audit --no-fund || npm install --no-audit --no-fund

up:
	$(COMPOSE) up -d

## wait: block until /healthz answers, so specs never race the boot
wait:
	@echo "waiting for mon-server on https://localhost:$(MON_PORT)/healthz"
	@i=0; until curl -ksSf "https://localhost:$(MON_PORT)/healthz" >/dev/null 2>&1; do \
		i=$$((i+1)); \
		if [ $$i -ge $(WAIT_SECONDS) ]; then echo "mon-server did not become healthy"; exit 1; fi; \
		sleep 1; \
	done; echo "mon-server is healthy"

test:
	npx playwright test

down:
	-$(COMPOSE) down -v --remove-orphans

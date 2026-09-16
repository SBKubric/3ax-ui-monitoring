GO ?= go
BIN ?= bin

.PHONY: build test vet race clean

build:
	$(GO) build -o $(BIN)/mon-server ./cmd/mon-server
	$(GO) build -o $(BIN)/mon-client ./cmd/mon-client

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

race:
	$(GO) test -race -count=1 ./...

clean:
	rm -rf $(BIN)

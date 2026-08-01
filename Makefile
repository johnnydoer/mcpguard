SHELL := /bin/bash
BINARY := mcpguard
PKGS := ./...

.PHONY: build test test-short lint fuzz cover clean install-tools

build:
	go build -trimpath -ldflags "-s -w -X main.version=$$(git describe --tags --always --dirty)" \
		-o $(BINARY) ./cmd/mcpguard

test:
	go test -race -count=1 $(PKGS)

# Skips integration tests that spawn a real MCP server. Used as the inner loop.
test-short:
	go test -short -race -count=1 $(PKGS)

lint:
	golangci-lint run

# Each fuzz target gets a bounded run in CI; longer local runs are manual.
fuzz:
	go test -run='^$$' -fuzz=FuzzPathCanonicalization -fuzztime=60s ./internal/canon
	go test -run='^$$' -fuzz=FuzzMatcherMatch -fuzztime=60s ./internal/policy
	go test -run='^$$' -fuzz=FuzzDecodeMessage -fuzztime=60s ./internal/protocol

cover:
	go test -race -coverprofile=coverage.out -covermode=atomic $(PKGS)
	go tool cover -func=coverage.out | tail -1

clean:
	rm -f $(BINARY) coverage.out

install-tools:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

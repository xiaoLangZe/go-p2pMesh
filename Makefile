# go-p2pmesh — build & release entry points
#
# Standard targets:
#
#   make build        build the two binaries for the host
#   make test         run all tests (CGO disabled — invariant)
#   make vet          go vet over the whole module
#   make sql-check    run the SQL safety gate (scripts/check-sql.sh)
#   make cross        cross-compile both binaries for all six targets
#   make playground   build Linux amd64/arm64 binaries for the RLN
#   make package      assemble dist/ archives from the cross binaries
#   make release      full pre-release gate: fmt-check, vet, test,
#                     sql-check, cross, package
#
# Every target runs with CGO_ENABLED=0: a CGO leak must fail here,
# not in the field. Machine-dependent code lives behind build tags.
SHELL := /usr/bin/env bash

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
DIRTY   := $(shell git status --porcelain 2>/dev/null | wc -l | tr -d ' ')
GOFLAGS := -trimpath
GO      := CGO_ENABLED=0 GOFLAGS='$(GOFLAGS)' go

GOOSES  := linux darwin windows
GOARCHS := amd64 arm64
BINS    := $(addprefix dist/bin/gop2pmesh-server-,)

.PHONY: build test vet sql-check cross package release fmt-check clean

build:
	$(GO) build -o gop2pmesh-server ./cmd/server
	$(GO) build -o gop2pmesh-client ./cmd/client

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

sql-check:
	bash scripts/check-sql.sh

fmt-check:
	@test -z "$$(gofmt -l cmd internal pkg scripts)" || \
		{ echo "gofmt needed on:"; gofmt -l cmd internal pkg scripts; exit 1; }

cross:
	@mkdir -p dist/bin
	@for goos in $(GOOSES); do \
		for goarch in $(GOARCHS); do \
			ext=""; [ "$$goos" = windows ] && ext=".exe"; \
			suffix="$$goos-$$goarch"; \
			CGO_ENABLED=0 GOOS=$$goos GOARCH=$$goarch GOFLAGS='$(GOFLAGS)' \
				go build -o "dist/bin/gop2pmesh-server-$$suffix$$ext" ./cmd/server || exit 1; \
			CGO_ENABLED=0 GOOS=$$goos GOARCH=$$goarch GOFLAGS='$(GOFLAGS)' \
				go build -o "dist/bin/gop2pmesh-client-$$suffix$$ext" ./cmd/client || exit 1; \
		done; \
	done
	@echo "cross binaries in dist/bin/"

package: cross
	VERSION=$(VERSION) bash scripts/release.sh package

release: fmt-check vet test sql-check package
	@echo "release candidate built: dist/ VERSION=$(VERSION)"
	@echo "next: scripts/release.sh audit  (full pre-delivery security audit)"

clean:
	rm -rf dist gop2pmesh-server gop2pmesh-client
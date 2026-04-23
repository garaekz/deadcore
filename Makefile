SHELL := /bin/bash

.PHONY: help build test fmt vet run clean

CARGO ?= cargo

## help: Show this help
help:
	@echo "Canonical tasks live in .cargo/config.toml and run everywhere via cargo aliases:"
	@echo "  cargo ox-build"
	@echo "  cargo ox-test"
	@echo "  cargo ox-fmt"
	@echo "  cargo ox-vet"
	@echo "  cargo ox-clean"
	@echo "  cargo ox-run --manifest fixtures/minimal.manifest.json"
	@echo ""
	@echo "Unix convenience wrapper:"
	@awk 'BEGIN {FS=":.*##"} /^[a-zA-Z0-9_\-]+:.*##/ {printf "  make %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST) | sort

## build: Run cargo ox-build
build:
	$(CARGO) ox-build

## test: Run cargo ox-test
test:
	$(CARGO) ox-test

## fmt: Run cargo ox-fmt
fmt:
	$(CARGO) ox-fmt

## vet: Run cargo ox-vet
vet:
	$(CARGO) ox-vet

## run: Run cargo ox-run with a manifest (usage: make run MANIFEST=path/to/manifest.json [OUT=delta.json])
run:
	@if [ -z "$(MANIFEST)" ]; then \
		echo "Usage: make run MANIFEST=path/to/manifest.json [OUT=delta.json]"; \
		exit 1; \
	fi
	@if [ -n "$(OUT)" ]; then \
		$(CARGO) ox-run --manifest $(MANIFEST) --out $(OUT); \
	else \
		$(CARGO) ox-run --manifest $(MANIFEST); \
	fi

## clean: Run cargo ox-clean
clean:
	$(CARGO) ox-clean

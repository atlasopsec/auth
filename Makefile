# Shared commands for this repo, adapted from the Makefile template in
# jakefrenzel/engineering-standards (standards/local-development.md).
#
# This repo is a library plus a Next.js template, so it has no dev server,
# local services, or seed data: no make dev, up, down, migrate, seed, or
# reset-db. Go tools come from tools/go.mod, so importers don't inherit them.

TOOL := go tool -modfile=tools/go.mod
WEB := templates/nextjs

.DEFAULT_GOAL := help
.PHONY: help setup test e2e lint fmt check generate migration

help: ## List commands
	@grep -E '^[a-z0-9-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  make %-12s %s\n", $$1, $$2}'

setup: ## Install Go modules, tools, and the template's dependencies
	go mod download
	cd tools && go mod download
	pnpm --dir $(WEB) install --frozen-lockfile

test: ## Run the Go tests and the template's unit tests
	go test -race ./...
	pnpm --dir $(WEB) test

e2e: ## Run the template's end-to-end tests (needs E2E_DATABASE_URL)
	pnpm --dir $(WEB) test:e2e

lint: ## Check formatting, lint, generated code, known vulnerabilities, and types
	@out=$$($(TOOL) goimports -l .); if [ -n "$$out" ]; then echo "Not formatted (run make fmt):"; echo "$$out"; exit 1; fi
	$(TOOL) golangci-lint run
	$(TOOL) sqlc diff
	$(TOOL) govulncheck ./...
	pnpm --dir $(WEB) format:check
	pnpm --dir $(WEB) lint
	pnpm --dir $(WEB) typecheck

fmt: ## Format all files
	$(TOOL) goimports -w .
	pnpm --dir $(WEB) format

check: lint test ## Everything to run before opening a PR

generate: ## Regenerate the sqlc code in internal/db
	$(TOOL) sqlc generate

migration: ## Create a migration: make migration name=add_invoices
	@test -n "$(name)" || (echo "usage: make migration name=add_invoices"; exit 1)
	$(TOOL) goose -dir internal/migrations -s create $(name) sql

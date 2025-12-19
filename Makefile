help: ## Show this help message
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ { printf "  %-15s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

check: ## Run linting checks
	golangci-lint run

test: ## Run tests with coverage
	go test ./... -cover

build: ## Build the webhook binary
	go build -ldflags "-w -s" -o kube-pep-webhook ./cmd/kube-pep-webhook

run: ## Run the webhook locally (requires env vars)
	go run ./cmd/kube-pep-webhook

.PHONY: help check test build run


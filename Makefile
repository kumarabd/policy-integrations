.PHONY: help build seed webhook

help:
	@echo "policy-integrations - Kubernetes integration for Policy Machine"
	@echo ""
	@echo "Targets:"
	@echo "  build   - Build both binaries"
	@echo "  seed    - Build policy-seed-k8s"
	@echo "  webhook - Build kube-pep-webhook"

build: seed webhook

seed:
	go build -o policy-seed-k8s ./cmd/policy-seed-k8s

webhook:
	go build -o kube-pep-webhook ./cmd/kube-pep-webhook

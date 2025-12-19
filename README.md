# Policy Integrations

A standalone service for Kubernetes authorization webhook integration with the Policy Machine PDP (Policy Decision Point).

## Overview

Policy Integrations provides a production-ready Kubernetes authorization webhook that enforces access to the Kubernetes API by consulting a Policy Decision Point (PDP) via the PEP SDK. This service is designed to be deployed as a Kubernetes webhook authorizer.

**Note**: This repository contains Kubernetes-specific implementations. The generic PEP SDK is maintained in the [policy-sdk-go](https://github.com/kumarabd/policy-sdk-go) repository.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│         Kubernetes API Server                            │
│                                                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Authorization Webhook (this service)           │  │
│  │  - Receives SubjectAccessReview requests        │  │
│  │  - Maps K8s requests to policy requests         │  │
│  │  - Calls PDP via PEP SDK                        │  │
│  │  - Returns allow/deny decision                  │  │
│  └──────────────────────────────────────────────────┘  │
└──────────────────────┬──────────────────────────────────┘
                       │
                       │ HTTP/HTTPS
                       ▼
┌─────────────────────────────────────────────────────────┐
│              PEP SDK (from policy-sdk-go)                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐│
│  │ Runtime  │  │  Client  │  │  Cache   │  │Telemetry││
│  └──────────┘  └──────────┘  └──────────┘  └─────────┘│
└──────────────────────┬──────────────────────────────────┘
                       │
                       │ HTTP/HTTPS
                       ▼
┌─────────────────────────────────────────────────────────┐
│         Policy Decision Point (PDP)                     │
│         (policy-machine server)                         │
└─────────────────────────────────────────────────────────┘
```

## Components

### 1. PEP SDK (Dependency)

The generic PEP SDK is imported from `github.com/kumarabd/policy-sdk-go`. It provides:
- **HTTP Client**: Calls the PDP for authorization decisions
- **Decision Cache**: LRU+TTL cache for performance
- **Version Provider**: Tracks policy versions for cache invalidation
- **Telemetry**: Structured logging and metrics hooks
- **Runtime**: Orchestrates the complete evaluation flow

### 2. Kubernetes Mapper (`pkg/k8s/mapper/`)

Converts Kubernetes `SubjectAccessReview` requests into generic policy requests:
- Maps Kubernetes users/groups to policy subjects
- Maps Kubernetes resources to policy objects
- Maps Kubernetes verbs to policy actions
- Handles both resource and non-resource attributes

### 3. Webhook Service (`pkg/k8s/webhook/`)

The main webhook implementation:
- **Server**: HTTPS server with TLS/mTLS support
- **Handlers**: Kubernetes webhook authorizer endpoint
- **Middleware**: Request ID, timeout, access logging
- **Circuit Breaker**: Protects against PDP failures
- **Metrics**: Prometheus-compatible metrics endpoint
- **Debug Mode**: Explain endpoint with security controls

### 4. Conventions (`pkg/k8s/conventions/`)

Canonical naming conventions for Kubernetes actions and object IDs:
- Action format: `k8s.<verb>.<resource>` or `k8s.<verb>.<group>.<resource>`
- Object ID format: `k8s://{cluster}/ns/{namespace}/{group}/{resource}/{name}`

### 5. Policy Seeder (`pkg/integrations/k8s/seeder/`)

Tools for seeding Kubernetes-aware policy into the PDP:
- RBAC import from Kubernetes YAML/JSON
- Policy bootstrap and merge modes
- Idempotent operations

## Quick Start

### Prerequisites

- Go 1.23.5 or higher
- Access to a Policy Machine PDP server
- TLS certificates for the webhook (or self-signed for dev)

### Setup

1. **Clone this repository**:
```bash
git clone https://github.com/kumarabd/policy-integrations.git
cd policy-integrations
```

2. **Set up dependency on policy-sdk-go**:

For local development, add a replace directive to `go.mod`:
```bash
echo "replace github.com/kumarabd/policy-sdk-go => ../policy-sdk-go" >> go.mod
```

Or if policy-sdk-go is published as a module, it will be fetched automatically.

3. **Install dependencies**:
```bash
go mod download
```

### Configuration

The webhook is configured via environment variables:

```bash
# Required
export PDP_BASE_URL="http://localhost:8500"
export CLUSTER_ID="dev-cluster"
export TLS_CERT_FILE="/path/to/cert.pem"
export TLS_KEY_FILE="/path/to/key.pem"

# Optional
export LISTEN_ADDR=":8443"
export TENANT_ID="tenant-123"
export FAIL_MODE="fail_closed"  # or "fail_open"
export SDK_CACHE_MAX_ENTRIES=50000
export SDK_CACHE_TTL=10s
export PDP_TIMEOUT=100ms
export REQUEST_TIMEOUT=200ms
```

### Build

```bash
make build
# or
go build -o kube-pep-webhook ./cmd/kube-pep-webhook
```

### Run

```bash
./kube-pep-webhook
```

### Deploy to Kubernetes

See `deploy/kube-pep-webhook/` for Kubernetes manifests:

```bash
kubectl apply -f deploy/kube-pep-webhook/
```

## Dependencies

This project depends on:
- **policy-sdk-go**: For the generic PEP SDK (`github.com/kumarabd/policy-sdk-go`)

For local development, use a replace directive in `go.mod`:
```go
replace github.com/kumarabd/policy-sdk-go => ../policy-sdk-go
```

## Project Structure

```
policy-integrations/
├── cmd/
│   └── kube-pep-webhook/     # Main entry point
├── pkg/
│   ├── k8s/                  # Kubernetes integration
│   │   ├── conventions/      # K8s naming conventions
│   │   ├── mapper/            # K8s request mapper
│   │   └── webhook/           # Webhook service
│   └── integrations/
│       └── k8s/              # K8s policy seeding
│           ├── conventions/  # Conventions (duplicate, can be consolidated)
│           └── seeder/       # Policy seeder
├── deploy/
│   └── kube-pep-webhook/     # Kubernetes manifests
└── README.md
```

## License

MIT

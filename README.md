# Policy Integrations

Kubernetes integration for the Policy Machine PDP. Two components, developed step by step:

## Components

### 1. Seeder (`cmd/policy-seed-k8s`)
- Connects to a Kubernetes cluster
- Reads existing RBAC and resource state
- Writes that state into the policy machine

### 2. Webhook (`cmd/kube-pep-webhook`)
- Acts as a Kubernetes authorization webhook (enforcement point)
- Receives SubjectAccessReview requests from the API server
- Uses the SDK to call the policy machine for allow/deny decisions

## Prerequisites

- Go 1.21+
- Policy Machine PDP (for both components)
- Kubernetes cluster (for seeder)

## Build

```bash
go build -o policy-seed-k8s ./cmd/policy-seed-k8s
go build -o kube-pep-webhook ./cmd/kube-pep-webhook
```

## Run

```bash
./policy-seed-k8s
./kube-pep-webhook
```

## Project Structure

```
policy-integrations/
├── cmd/
│   ├── policy-seed-k8s/    # Seeder binary
│   └── kube-pep-webhook/   # Webhook binary
├── docs/                   # Documentation
└── README.md
```

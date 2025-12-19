# Kubernetes Authorization Webhook PEP

This package implements a Kubernetes authorization webhook that enforces access to the Kubernetes API by consulting a Policy Decision Point (PDP) via the PEP SDK.

## Overview

The webhook server:
- Implements the Kubernetes `SubjectAccessReview` webhook authorizer interface
- Maps Kubernetes authorization requests to policy requests using the k8s mapper
- Calls the PEP SDK to make authorization decisions
- Returns Kubernetes-compliant authorization responses
- Includes hardening: timeouts, caching, fail modes, request ID propagation, tenant resolution

## Features

- **HTTPS/TLS**: Secure communication with Kubernetes API server
- **Caching**: Decision caching via SDK (LRU + TTL)
- **Version-aware**: Policy version tracking for cache invalidation
- **Fail modes**: Configurable fail-closed (default) or fail-open behavior
- **Explain mode**: Optional debug mode with trace information (requires debug token)
- **Health checks**: `/healthz` and `/readyz` endpoints
- **Metrics**: `/metrics` endpoint (placeholder, can be enhanced)
- **Structured logging**: JSON logs with request IDs

## Configuration

The webhook is configured via environment variables:

### Required

- `PDP_BASE_URL`: Base URL of the Policy Decision Point (e.g., `http://localhost:8500`)
- `CLUSTER_ID`: Stable identifier for the Kubernetes cluster (e.g., `dev-cluster`)
- `TLS_CERT_FILE`: Path to TLS certificate file
- `TLS_KEY_FILE`: Path to TLS private key file

### Optional

- `LISTEN_ADDR`: Address to listen on (default: `:8443`)
- `PDP_EVALUATE_PATH`: Path for evaluation requests (default: `/api/v1/evaluate`)
- `TENANT_ID`: Default tenant ID if not provided by header
- `TENANT_HEADER`: Header name for tenant ID (default: `X-Tenant-Id`)
- `SUBJECT_ID_MODE`: Subject ID format - `username` (default) or `uid`
- `ACTION_MODE`: Action format - `simple` (default) or `with_group`
- `FAIL_MODE`: Failure behavior - `fail_closed` (default) or `fail_open`
- `EXPLAIN_ENABLED`: Enable explain mode (default: `false`)
- `DEBUG_TOKEN`: Token required for explain mode (security check)
- `SDK_CACHE_MAX_ENTRIES`: Maximum cache entries (default: `50000`)
- `SDK_CACHE_TTL`: Cache TTL duration (default: `10s`)
- `VERSION_REFRESH_INTERVAL`: Version refresh interval (default: `2s`)
- `PDP_TIMEOUT`: Timeout for PDP requests (default: `100ms`)
- `REQUEST_TIMEOUT`: Timeout for webhook handler (default: `200ms`)
- `EXPLAIN_MAX_BYTES`: Maximum size of explain trace logs (default: `16384`)
- `TLS_CLIENT_CA_FILE`: Path to CA certificate file for client cert verification (mTLS)
- `INSECURE_SKIP_CLIENT_VERIFY`: Skip client cert verification (dev only, default: `false`)
- `MAX_REQUEST_SIZE`: Maximum request body size in bytes (default: `1048576` = 1MB)
- `DEBUG_CLIENT_CNS`: Comma-separated list of allowed client cert CNs for debug mode

## Generating TLS Certificates

### For Development (Self-Signed)

```bash
# Generate private key
openssl genrsa -out webhook-key.pem 2048

# Generate certificate signing request
openssl req -new -key webhook-key.pem -out webhook.csr \
  -subj "/CN=pep-webhook.default.svc"

# Generate self-signed certificate
openssl x509 -req -in webhook.csr -signkey webhook-key.pem \
  -out webhook-cert.pem -days 365

# Clean up CSR
rm webhook.csr
```

### For Production

Use a proper certificate authority (CA) or Kubernetes cert-manager to generate certificates.

## Kubernetes Configuration

### kube-apiserver Authorization Webhook Configuration

For authorization webhooks, Kubernetes requires configuration in the kube-apiserver. Create an authorization webhook configuration file:

**`/etc/kubernetes/authorization-webhook-config.yaml`**:

```yaml
apiVersion: v1
kind: Config
clusters:
  - name: pep-webhook
    cluster:
      server: https://pep-webhook.default.svc:8443/authorize
      # CA certificate that signed the webhook server certificate
      certificate-authority-data: <base64-encoded-CA-certificate>
users:
  - name: kube-apiserver
    user:
      # Client certificate for mTLS (if TLS_CLIENT_CA_FILE is configured)
      client-certificate-data: <base64-encoded-client-certificate>
      client-key-data: <base64-encoded-client-key>
current-context: pep-webhook
contexts:
  - name: pep-webhook
    context:
      cluster: pep-webhook
      user: kube-apiserver
```

**kube-apiserver flags**:

Add these flags to your kube-apiserver manifest or configuration:

```yaml
spec:
  containers:
  - name: kube-apiserver
    command:
    - kube-apiserver
    - --authorization-mode=Node,RBAC,Webhook
    - --authorization-webhook-config-file=/etc/kubernetes/authorization-webhook-config.yaml
    # Optional: timeout for webhook calls
    - --authorization-webhook-cache-authorized-ttl=5m
    - --authorization-webhook-cache-unauthorized-ttl=30s
```

### Client Certificate Setup (mTLS)

To enable mutual TLS authentication:

1. **Generate client certificate for kube-apiserver**:

```bash
# Generate CA for client certs (if not using existing CA)
openssl genrsa -out client-ca-key.pem 2048
openssl req -x509 -new -nodes -key client-ca-key.pem -days 365 \
  -out client-ca-cert.pem -subj "/CN=pep-webhook-client-ca"

# Generate client cert for kube-apiserver
openssl genrsa -out kube-apiserver-key.pem 2048
openssl req -new -key kube-apiserver-key.pem -out kube-apiserver.csr \
  -subj "/CN=kube-apiserver"
openssl x509 -req -in kube-apiserver.csr -CA client-ca-cert.pem \
  -CAkey client-ca-key.pem -CAcreateserial -out kube-apiserver-cert.pem -days 365
```

2. **Configure webhook**:

Set `TLS_CLIENT_CA_FILE=/etc/tls/ca.crt` (pointing to `client-ca-cert.pem`)

3. **Update authorization-webhook-config.yaml**:

Use the base64-encoded client certificate and key:

```bash
cat kube-apiserver-cert.pem | base64 -w 0
cat kube-apiserver-key.pem | base64 -w 0
```

4. **Set DEBUG_CLIENT_CNS**:

If using debug mode, set `DEBUG_CLIENT_CNS=kube-apiserver,pep-admin` to allow specific client cert CNs.

### CA Bundle for Webhook Server Certificate

The kube-apiserver needs to trust the webhook server's TLS certificate. Include the CA that signed the webhook certificate in `certificate-authority-data`:

```bash
# If using self-signed cert, use the cert itself
cat webhook-cert.pem | base64 -w 0

# If using a CA-signed cert, use the CA cert
cat ca-cert.pem | base64 -w 0
```

## Deployment

### Example Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pep-webhook
  namespace: default
spec:
  replicas: 2
  selector:
    matchLabels:
      app: pep-webhook
  template:
    metadata:
      labels:
        app: pep-webhook
    spec:
      containers:
      - name: webhook
        image: policy-machine/pep-webhook:latest
        ports:
        - containerPort: 8443
        env:
        - name: PDP_BASE_URL
          value: "http://policy-engine:8500"
        - name: CLUSTER_ID
          value: "prod-cluster"
        - name: TLS_CERT_FILE
          value: "/etc/tls/tls.crt"
        - name: TLS_KEY_FILE
          value: "/etc/tls/tls.key"
        - name: TENANT_ID
          value: "tenant-123"
        - name: FAIL_MODE
          value: "fail_closed"
        volumeMounts:
        - name: tls
          mountPath: /etc/tls
          readOnly: true
      volumes:
      - name: tls
        secret:
          secretName: pep-webhook-tls
---
apiVersion: v1
kind: Service
metadata:
  name: pep-webhook
  namespace: default
spec:
  selector:
    app: pep-webhook
  ports:
  - port: 8443
    targetPort: 8443
    protocol: TCP
  type: ClusterIP
```

## Testing

### Local Testing with curl

```bash
# Set environment variables
export PDP_BASE_URL="http://localhost:8500"
export CLUSTER_ID="dev-cluster"
export TLS_CERT_FILE="./webhook-cert.pem"
export TLS_KEY_FILE="./webhook-key.pem"

# Start the webhook server
go run cmd/kube-pep-webhook/main.go

# Test authorization request
curl -k https://localhost:8443/authorize \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "apiVersion": "authorization.k8s.io/v1",
    "kind": "SubjectAccessReview",
    "spec": {
      "user": "alice",
      "groups": ["devs"],
      "resourceAttributes": {
        "verb": "get",
        "resource": "pods",
        "namespace": "default",
        "name": "nginx"
      }
    }
  }'
```

### Example Response

```json
{
  "apiVersion": "authorization.k8s.io/v1",
  "kind": "SubjectAccessReview",
  "status": {
    "allowed": true,
    "denied": false,
    "reason": "ALLOW",
    "auditAnnotations": {
      "pep.version_id": "rev:123",
      "pep.subject_id": "alice",
      "pep.action": "k8s.get.pods",
      "pep.object_id": "k8s://dev-cluster/ns/default/core/pods/nginx"
    }
  }
}
```

## Explain Mode

To enable explain mode for debugging:

1. Set `EXPLAIN_ENABLED=true`
2. Set `DEBUG_TOKEN=<your-secret-token>`
3. Make a request with `?explain=1` query parameter and `X-Debug-Token` header:

```bash
curl -k https://localhost:8443/authorize?explain=1 \
  -X POST \
  -H "Content-Type: application/json" \
  -H "X-Debug-Token: <your-secret-token>" \
  -d '{...}'
```

The trace information will be logged (not returned in the response) with size limits.

## Resource Limits

Recommended resource limits for production:

```yaml
resources:
  requests:
    memory: "128Mi"
    cpu: "100m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

## High Availability

- Deploy multiple replicas (2-3 recommended)
- Use a Kubernetes Service with load balancing
- Ensure PDP is highly available
- Configure appropriate timeouts for fail-fast behavior
- Monitor cache hit rates and adjust `SDK_CACHE_MAX_ENTRIES` and `SDK_CACHE_TTL` based on workload

## Monitoring

- Health endpoint: `GET /healthz`
- Readiness endpoint: `GET /readyz`
- Metrics endpoint: `GET /metrics` (placeholder, enhance with actual metrics)
- Structured logs: JSON format with request IDs for correlation

## Security Considerations

- Always use TLS in production
- Rotate certificates regularly
- Use strong debug tokens for explain mode
- Limit network access to PDP
- Monitor for unauthorized access attempts
- Use fail-closed mode for production (default)

## Troubleshooting

### Webhook not receiving requests

- Check kube-apiserver logs for webhook configuration errors
- Verify TLS certificates are valid and trusted
- Ensure service is accessible from kube-apiserver
- Check network policies and firewall rules

### Authorization always denies

- Check PDP connectivity and logs
- Verify tenant configuration
- Check fail mode setting (fail_closed vs fail_open)
- Review policy rules in PDP

### High latency

- Adjust `SDK_CACHE_TTL` and `SDK_CACHE_MAX_ENTRIES`
- Check PDP response times
- Review `PDP_TIMEOUT` and `REQUEST_TIMEOUT` settings
- Monitor cache hit rates


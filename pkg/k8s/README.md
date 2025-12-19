# Kubernetes Domain Adapter

This package provides a domain adapter for converting Kubernetes authorization requests into the PEP SDK's generic policy requests. It implements the mapping layer between Kubernetes-specific authorization semantics and the SDK's policy evaluation interface.

## Overview

The Kubernetes mapper (`pkg/pep/k8s/mapper`) converts Kubernetes `SubjectAccessReview`-style authorization requests into `policy.PolicyRequest` objects that can be evaluated by the PEP SDK.

**Note**: This package is **not** an enforcement point itself. It only provides the mapping logic. The actual Kubernetes webhook server that uses this mapper will be built in a later step.

## Package Structure

- **`mapper/types.go`**: Kubernetes authorization request types (UserInfo, ResourceAttributes, NonResourceAttributes, AuthorizationRequest)
- **`mapper/mapper.go`**: Mapper configuration and main mapper implementation
- **`mapper/mapping.go`**: Mapping rules for converting Kubernetes requests to policy requests
- **`examples/preflight/main.go`**: Example demonstrating mapper usage with the SDK

## Mapping Conventions

### Subject Mapping

The mapper converts Kubernetes `UserInfo` into a policy `EntityRef`:

- **Subject Type**: Always `"SUBJECT"`
- **Subject ID**: 
  - If `SubjectIDMode == "uid"` and `User.UID` is non-empty: use `User.UID`
  - Otherwise: use `User.Username`
- **Subject Attributes**:
  - If `IncludeGroupsAsAttrs == true`: includes `groups` attribute with comma-separated group list
  - Includes `extra.*` attributes from `User.Extra` (with size limits to prevent huge payloads)
  - Limits: max 10 extra keys, max 10 values per key (truncation noted in attributes)

### Action Mapping

#### Resource Requests

**Default mode** (`ActionMode == "k8s.<verb>.<resource>"`):
- Format: `k8s.<verb>.<resource>[/<subresource>]`
- Examples:
  - `k8s.get.pods`
  - `k8s.create.deployments`
  - `k8s.get.pods/log` (with subresource)

**Group-aware mode** (`ActionMode == "k8s.<verb>.<group>.<resource>"`):
- Format: `k8s.<verb>.<group>.<resource>[/<subresource>]`
- Examples:
  - `k8s.get.core.pods`
  - `k8s.get.apps.deployments`
  - `k8s.get.networking.k8s.io.ingresses`

#### Non-Resource Requests

- Format: `k8s.<verb>.nonresource`
- Examples:
  - `k8s.get.nonresource`
  - `k8s.post.nonresource`

### Object ID Mapping

#### Resource Objects (Canonical Format)

Format: `k8s://{clusterID}/ns/{namespace or _cluster}/{group or core}/{resource}/{name or _all}[/{subresource}]`

Examples:
- `k8s://dev-cluster/ns/default/core/pods/nginx`
- `k8s://dev-cluster/ns/_cluster/core/nodes/node-1`
- `k8s://dev-cluster/ns/default/apps/deployments/my-app`
- `k8s://dev-cluster/ns/default/core/pods/nginx/log` (with subresource)
- `k8s://dev-cluster/ns/default/core/pods/_all` (collection operation)

Rules:
- Cluster-scoped resources use `_cluster` as namespace
- Empty API group becomes `core`
- Empty name becomes `_all` (represents collection)
- Subresource appended with `/` if present

#### Non-Resource Objects

Format: `k8s://{clusterID}/nonresource{path}`

Examples:
- `k8s://dev-cluster/nonresource/api`
- `k8s://dev-cluster/nonresource/healthz`
- `k8s://dev-cluster/nonresource/metrics`

### Context Mapping

The mapper always includes:
- `cluster`: The cluster ID from configuration
- `verb`: The Kubernetes verb (e.g., "get", "create", "list")

For resource requests, also includes:
- `apiGroup`: The API group (or "core" if empty)
- `version`: The API version
- `resource`: The resource type
- `subresource`: The subresource (if present)
- `namespace`: The namespace (if present)
- `name`: The resource name (if present)

For non-resource requests, also includes:
- `path`: The HTTP path

If `RequestURI` is provided, it's included in context for both types.

## Configuration

The mapper is configured via `mapper.Config`:

```go
cfg := mapper.Config{
    ClusterID:            "dev-cluster",        // Required: stable cluster identifier
    TenantID:             "tenant-123",         // Optional: default tenant
    SubjectIDMode:        "username",            // "uid" or "username" (default: "username")
    IncludeGroupsAsAttrs:  true,                 // Include groups in subject attributes (default: true)
    ActionMode:            "k8s.<verb>.<resource>", // Action format (default)
    ObjectIDMode:         "canonical",          // Object ID format (default: "canonical")
}
```

### Configuration Options

- **ClusterID** (required): A stable identifier for the Kubernetes cluster. Used in object IDs.
- **TenantID** (optional): Default tenant ID if not provided by the caller. Can also be set via context.
- **SubjectIDMode**: 
  - `"username"` (default): Use `User.Username` as subject ID
  - `"uid"`: Use `User.UID` as subject ID (fallback to username if UID empty)
- **IncludeGroupsAsAttrs**: If `true`, includes user groups in subject attributes as `groups` (comma-separated).
- **ActionMode**:
  - `"k8s.<verb>.<resource>"` (default): Simple format without API group
  - `"k8s.<verb>.<group>.<resource>"`: Include API group in action
- **ObjectIDMode**: Currently only `"canonical"` is supported (default).

## Usage Example

```go
import (
    "context"
    "github.com/kumarabd/policy-integrations/pkg/k8s/mapper"
    "github.com/kumarabd/policy-sdk-go/policy"
    "github.com/kumarabd/policy-sdk-go/runtime"
)

// Create mapper
k8sMapper, err := mapper.New(mapper.Config{
    ClusterID: "dev-cluster",
    TenantID:  "tenant-123",
})
if err != nil {
    // Handle error
}

// Create Kubernetes authorization request
authReq := mapper.AuthorizationRequest{
    User: mapper.UserInfo{
        Username: "alice",
        Groups:   []string{"devs"},
    },
    ResourceAttributes: &mapper.ResourceAttributes{
        Verb:      "get",
        Resource:  "pods",
        Namespace: "default",
        Name:      "nginx",
    },
}

// Map to policy request
ctx := policy.WithTenant(context.Background(), "tenant-123")
policyReq, err := k8sMapper.Map(ctx, authReq)
if err != nil {
    // Handle error
}

// Use with SDK
sdk := runtime.New(...)
result, err := sdk.Decide(ctx, policyReq)
```

## Validation

The mapper validates input requests and returns errors for:
- Empty username and UID (at least one required)
- Neither `resourceAttributes` nor `nonResourceAttributes` set
- Both `resourceAttributes` and `nonResourceAttributes` set
- Empty verb in resource or non-resource attributes
- Empty `ClusterID` in configuration

## Deterministic Behavior

The mapper is designed to be deterministic:
- No network calls (no PIP)
- No random values
- Stable object ID format
- Consistent attribute ordering (groups, then extra keys)

## Limitations

- **No Kubernetes client-go dependency**: Uses minimal structs that mirror Kubernetes types
- **No PIP integration**: Does not fetch additional policy information (that comes later)
- **Size limits**: Extra attributes are truncated to prevent huge payloads (max 10 keys, 10 values per key)
- **Single cluster**: Each mapper instance is configured for one cluster

## Next Steps

The next step is to build the actual Kubernetes webhook server that:
1. Receives Kubernetes `SubjectAccessReview` requests
2. Uses this mapper to convert them to policy requests
3. Calls the SDK to make decisions
4. Returns `SubjectAccessReview` responses

See `examples/preflight/main.go` for a complete working example.


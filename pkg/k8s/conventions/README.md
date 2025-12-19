# Kubernetes Policy Conventions

This package defines the canonical conventions for representing Kubernetes resources and actions in the policy model. These conventions **must** match the format used by the k8s mapper (`pkg/k8s/mapper`).

## Action Naming

### Resource Actions

**Simple format** (default):
```
k8s.<verb>.<resource>
```

Examples:
- `k8s.get.pods`
- `k8s.create.deployments`
- `k8s.delete.services`

**With API group**:
```
k8s.<verb>.<group>.<resource>
```

Examples:
- `k8s.get.core.pods`
- `k8s.get.apps.deployments`
- `k8s.get.networking.k8s.io.ingresses`

**With subresource**:
```
k8s.<verb>.<resource>/<subresource>
```

Examples:
- `k8s.get.pods/log`
- `k8s.get.pods/status`
- `k8s.get.deployments/scale`

### Non-Resource Actions

```
k8s.<verb>.nonresource
```

Examples:
- `k8s.get.nonresource`
- `k8s.post.nonresource`

### Common Verbs

- `get` - Read a single resource
- `list` - List resources
- `watch` - Watch resources
- `create` - Create a resource
- `update` - Update a resource
- `patch` - Patch a resource
- `delete` - Delete a resource
- `deletecollection` - Delete multiple resources
- `impersonate` - Impersonate a user
- `bind` - Bind a role
- `escalate` - Escalate privileges
- `use` - Use a resource (e.g., PodSecurityPolicy)

## Object ID Format

### Resource Objects

**Format**:
```
k8s://{clusterID}/ns/{namespace|_cluster}/{group|core}/{resource}/{name|_all}[/{subresource}]
```

**Rules**:
- Cluster-scoped resources use `_cluster` as namespace
- Empty API group becomes `core`
- Empty name becomes `_all` (represents collection)
- Subresource appended with `/` if present

**Examples**:
- `k8s://dev-cluster/ns/default/core/pods/nginx` - Pod in default namespace
- `k8s://dev-cluster/ns/_cluster/core/nodes/node-1` - Cluster-scoped node
- `k8s://dev-cluster/ns/default/apps/deployments/my-app` - Deployment with API group
- `k8s://dev-cluster/ns/default/core/pods/nginx/log` - Pod log subresource
- `k8s://dev-cluster/ns/default/core/pods/_all` - All pods in namespace (collection)

### Non-Resource Objects

**Format**:
```
k8s://{clusterID}/nonresource{path}
```

**Examples**:
- `k8s://dev-cluster/nonresource/api`
- `k8s://dev-cluster/nonresource/healthz`
- `k8s://dev-cluster/nonresource/metrics`

## Usage

```go
import "github.com/kumarabd/policy-integrations/pkg/k8s/conventions"

// Build action
action := conventions.BuildResourceAction("get", "core", "pods", "", conventions.ActionModeSimple)
// Result: "k8s.get.pods"

// Build object ID
objectID := conventions.BuildResourceObjectID("dev-cluster", "default", "core", "pods", "nginx", "")
// Result: "k8s://dev-cluster/ns/default/core/pods/nginx"

// Parse object ID
clusterID, namespace, group, resource, name, subresource, err := 
    conventions.ParseResourceObjectID("k8s://dev-cluster/ns/default/core/pods/nginx")
```

## Consistency Requirements

These conventions **must** match:
1. The k8s mapper (`pkg/k8s/mapper/mapping.go`)
2. The webhook handler (which uses the mapper)
3. Any policy authoring tools or UIs

Any changes to these conventions must be coordinated across all components.


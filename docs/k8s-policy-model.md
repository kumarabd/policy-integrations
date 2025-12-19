# Kubernetes Policy Model

This document explains how Kubernetes authorization requests are modeled in the policy engine and how to author policies for Kubernetes.

## Overview

The policy engine uses a generic NGAC (Next Generation Access Control) model that can represent Kubernetes authorization semantics. The Kubernetes webhook PEP (`kube-pep-webhook`) maps Kubernetes `SubjectAccessReview` requests to the policy model, evaluates them, and returns authorization decisions.

## Request Mapping

### Kubernetes Request → Policy Model

When a Kubernetes API server sends a `SubjectAccessReview` request, it is mapped as follows:

#### Subject

- **Type**: Always `"SUBJECT"`
- **ID**: User identifier (username or UID, configurable)
- **Attributes**: 
  - `groups`: Comma-separated list of user groups
  - `extra.*`: Additional user attributes (truncated for size)

**Example**:
```json
{
  "id": "alice",
  "type": "SUBJECT",
  "attributes": {
    "groups": "devs,engineers"
  }
}
```

#### Object

- **Type**: Always `"OBJECT"`
- **ID**: Canonical Kubernetes URI format

**Format for resources**:
```
k8s://{clusterID}/ns/{namespace|_cluster}/{group|core}/{resource}/{name|_all}[/{subresource}]
```

**Format for non-resources**:
```
k8s://{clusterID}/nonresource{path}
```

**Examples**:
- `k8s://dev-cluster/ns/default/core/pods/nginx` - Pod in default namespace
- `k8s://dev-cluster/ns/_cluster/core/nodes/node-1` - Cluster-scoped node
- `k8s://dev-cluster/ns/default/apps/deployments/my-app` - Deployment
- `k8s://dev-cluster/nonresource/api` - API endpoint

#### Action

**Format for resources**:
- Simple: `k8s.<verb>.<resource>`
- With group: `k8s.<verb>.<group>.<resource>`
- With subresource: `k8s.<verb>.<resource>/<subresource>`

**Format for non-resources**:
- `k8s.<verb>.nonresource`

**Examples**:
- `k8s.get.pods`
- `k8s.create.deployments`
- `k8s.get.pods/log`
- `k8s.get.apps.deployments`
- `k8s.get.nonresource`

## Policy Authoring

### Example Policies

#### 1. Namespace Reader

Allow users in the "readers" group to read resources in a namespace:

**Subject Set**: `k8s:ns:default:readers`
- Members: Users in the "readers" group

**Object Set**: `k8s:ns:default:resources`
- Objects: `k8s://cluster/ns/default/core/pods/_all`
- Objects: `k8s://cluster/ns/default/core/services/_all`
- Objects: `k8s://cluster/ns/default/core/configmaps/_all`

**Rule**:
- Subject: `k8s:ns:default:readers`
- Object: `k8s:ns:default:resources`
- Actions: `["k8s.get", "k8s.list", "k8s.watch"]`

#### 2. Cluster Administrator

Allow cluster admins full access to all resources:

**Subject Set**: `k8s:cluster-admins`
- Members: Users in the "cluster-admins" group

**Object Set**: `k8s:cluster-scoped:all`
- Objects: `k8s://cluster/ns/_cluster/core/nodes/_all`
- Objects: `k8s://cluster/ns/_cluster/core/namespaces/_all`
- Objects: `k8s://cluster/ns/_cluster/core/persistentvolumes/_all`

**Rule**:
- Subject: `k8s:cluster-admins`
- Object: `k8s:cluster-scoped:all`
- Actions: `["k8s.get", "k8s.list", "k8s.watch", "k8s.create", "k8s.update", "k8s.patch", "k8s.delete"]`

#### 3. Restricted Deletes

Deny deletion of critical resources:

**Subject Set**: `k8s:all-users` (all authenticated users)

**Object Set**: `k8s:critical-resources`
- Objects: `k8s://cluster/ns/_cluster/core/namespaces/kube-system`
- Objects: `k8s://cluster/ns/_cluster/core/nodes/_all`

**Deny Rule**:
- Subject: `k8s:all-users`
- Object: `k8s:critical-resources`
- Actions: `["k8s.delete"]`

#### 4. Pod Exec (Subresource)

Allow developers to exec into pods in their namespace:

**Subject Set**: `k8s:ns:default:developers`

**Object Set**: `k8s:ns:default:pods`
- Objects: `k8s://cluster/ns/default/core/pods/_all/exec`

**Rule**:
- Subject: `k8s:ns:default:developers`
- Object: `k8s:ns:default:pods`
- Actions: `["k8s.create.pods/exec"]`

## Policy Seeding

The `policy-seed-k8s` CLI tool helps bootstrap initial policy for a Kubernetes cluster.

### Basic Usage

```bash
# Bootstrap baseline policy
./policy-seed-k8s \
  --pdp-base-url=http://localhost:8500 \
  --tenant=tenant-123 \
  --cluster-id=dev-cluster \
  --mode=bootstrap

# Merge with existing policy (idempotent)
./policy-seed-k8s \
  --pdp-base-url=http://localhost:8500 \
  --tenant=tenant-123 \
  --cluster-id=dev-cluster \
  --mode=merge

# Dry run (see what would be created)
./policy-seed-k8s \
  --pdp-base-url=http://localhost:8500 \
  --tenant=tenant-123 \
  --cluster-id=dev-cluster \
  --mode=merge \
  --dry-run
```

### Importing from RBAC

You can import Kubernetes RBAC bindings from a JSON file:

**Example RBAC JSON** (`rbac.json`):
```json
{
  "bindings": [
    {
      "name": "admin-binding",
      "subjects": [
        {"kind": "User", "name": "alice"},
        {"kind": "Group", "name": "cluster-admins"}
      ],
      "roleRef": {
        "kind": "ClusterRole",
        "name": "cluster-admin",
        "apiGroup": "rbac.authorization.k8s.io"
      },
      "rules": [
        {
          "apiGroups": [""],
          "resources": ["*"],
          "verbs": ["*"]
        }
      ]
    }
  ]
}
```

**Import command**:
```bash
./policy-seed-k8s \
  --pdp-base-url=http://localhost:8500 \
  --tenant=tenant-123 \
  --cluster-id=dev-cluster \
  --mode=merge \
  --from-rbac-yaml=rbac.json
```

## Conventions Package

The `pkg/integrations/k8s/conventions` package provides helpers for building actions and object IDs that match the webhook mapper:

```go
import "github.com/kumarabd/policy-integrations/pkg/integrations/k8s/conventions"

// Build action
action := conventions.BuildResourceAction("get", "core", "pods", "", conventions.ActionModeSimple)
// Result: "k8s.get.pods"

// Build object ID
objectID := conventions.BuildResourceObjectID("dev-cluster", "default", "core", "pods", "nginx", "")
// Result: "k8s://dev-cluster/ns/default/core/pods/nginx"
```

## Webhook Integration

The webhook (`kube-pep-webhook`) uses the mapper (`pkg/k8s/mapper`) which implements these exact conventions. When a Kubernetes request arrives:

1. **Mapper converts** Kubernetes `SubjectAccessReview` → `PolicyRequest`
2. **SDK evaluates** the policy request using the engine
3. **Response** is converted back to `SubjectAccessReview` format

The conventions ensure consistency between:
- Policy authoring (using conventions package)
- Request mapping (webhook mapper)
- Policy storage (engine)

## Best Practices

1. **Use subject sets and object sets** for grouping rather than individual subjects/objects
2. **Use stable naming conventions** like `k8s:cluster-admins`, `k8s:ns:{namespace}:readers`
3. **Leverage object set wildcards** (`_all`) for collection operations
4. **Use deny rules** for baseline security (e.g., prevent deletion of critical resources)
5. **Version your policies** using the revision system
6. **Test with dry-run** before applying changes

## Common Patterns

### Pattern: Namespace Isolation

Create separate subject sets and object sets per namespace:

- Subject sets: `k8s:ns:{namespace}:readers`, `k8s:ns:{namespace}:writers`
- Object sets: `k8s:ns:{namespace}:resources`
- Rules: Map subject sets to object sets with appropriate actions

### Pattern: Role-Based Access

Map Kubernetes roles to policy:

- ClusterRole → Object set with cluster-scoped resources
- Role → Object set with namespace-scoped resources
- RoleBinding/ClusterRoleBinding → Subject set with bound subjects

### Pattern: Least Privilege

Start with deny-all, then add specific allow rules:

1. Create a deny rule: `k8s:all-users` → `k8s:all-resources` → `["*"]`
2. Add allow rules for specific use cases
3. Deny rules are evaluated first, so allows can override

## Troubleshooting

### Policy Not Working

1. **Check object IDs**: Ensure they match the canonical format
2. **Verify actions**: Use the conventions package to build actions
3. **Check subject/object sets**: Ensure members are correctly assigned
4. **Review rules**: Verify subject/object selectors match your sets

### Debugging

Use explain mode in the webhook:

```bash
curl -k https://localhost:8443/authorize?explain=1 \
  -X POST \
  -H "Content-Type: application/json" \
  -H "X-Debug-Token: <token>" \
  -d '{...}'
```

This will log trace information showing which rules matched.

## References

- [Kubernetes Authorization Overview](https://kubernetes.io/docs/reference/access-authn-authz/authorization/)
- [NGAC Policy Model](../README.md)
- [Webhook Documentation](../pkg/k8s/webhook/README.md)
- [Conventions Package](../pkg/integrations/k8s/conventions/README.md)


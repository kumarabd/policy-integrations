package conventions

import (
	"fmt"
	"strings"
)

// BuildResourceObjectID builds a canonical Kubernetes resource object ID.
// Format: k8s://{clusterID}/ns/{namespace|_cluster}/{group|core}/{resource}/{name|_all}[/{subresource}]
// This MUST match the format used in pkg/k8s/mapper/mapping.go
func BuildResourceObjectID(clusterID, namespace, group, resource, name, subresource string) string {
	// Handle cluster-scoped resources
	ns := namespace
	if ns == "" {
		ns = "_cluster"
	}
	
	// Handle API group
	apiGroup := group
	if apiGroup == "" {
		apiGroup = "core"
	}
	
	// Handle resource name
	resourceName := name
	if resourceName == "" {
		resourceName = "_all" // Collection operation
	}
	
	// Build base path
	parts := []string{
		"k8s://",
		clusterID,
		"/ns/",
		ns,
		"/",
		apiGroup,
		"/",
		resource,
		"/",
		resourceName,
	}
	
	// Append subresource if present
	if subresource != "" {
		parts = append(parts, "/", subresource)
	}
	
	return strings.Join(parts, "")
}

// BuildNonResourceObjectID builds a canonical Kubernetes non-resource object ID.
// Format: k8s://{clusterID}/nonresource{path}
func BuildNonResourceObjectID(clusterID, path string) string {
	// Ensure path starts with /
	if path == "" {
		path = "/"
	} else if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	
	return fmt.Sprintf("k8s://%s/nonresource%s", clusterID, path)
}

// ParseResourceObjectID parses a canonical resource object ID into its components.
// Returns: clusterID, namespace, group, resource, name, subresource, error
func ParseResourceObjectID(objectID string) (string, string, string, string, string, string, error) {
	// Format: k8s://{clusterID}/ns/{namespace}/{group}/{resource}/{name}[/{subresource}]
	if !strings.HasPrefix(objectID, "k8s://") {
		return "", "", "", "", "", "", fmt.Errorf("invalid object ID format: must start with k8s://")
	}
	
	// Remove k8s:// prefix
	rest := strings.TrimPrefix(objectID, "k8s://")
	
	// Split by /
	parts := strings.Split(rest, "/")
	if len(parts) < 6 {
		return "", "", "", "", "", "", fmt.Errorf("invalid object ID format: insufficient parts")
	}
	
	// parts[0] = clusterID
	// parts[1] = "ns"
	// parts[2] = namespace
	// parts[3] = group
	// parts[4] = resource
	// parts[5] = name
	// parts[6] (optional) = subresource
	
	clusterID := parts[0]
	if parts[1] != "ns" {
		return "", "", "", "", "", "", fmt.Errorf("invalid object ID format: expected 'ns'")
	}
	
	namespace := parts[2]
	if namespace == "_cluster" {
		namespace = ""
	}
	
	group := parts[3]
	if group == "core" {
		group = ""
	}
	
	resource := parts[4]
	name := parts[5]
	if name == "_all" {
		name = ""
	}
	
	subresource := ""
	if len(parts) > 6 {
		subresource = parts[6]
	}
	
	return clusterID, namespace, group, resource, name, subresource, nil
}

// ParseNonResourceObjectID parses a canonical non-resource object ID into its components.
// Returns: clusterID, path, error
func ParseNonResourceObjectID(objectID string) (string, string, error) {
	// Format: k8s://{clusterID}/nonresource{path}
	if !strings.HasPrefix(objectID, "k8s://") {
		return "", "", fmt.Errorf("invalid object ID format: must start with k8s://")
	}
	
	// Remove k8s:// prefix
	rest := strings.TrimPrefix(objectID, "k8s://")
	
	// Find /nonresource
	idx := strings.Index(rest, "/nonresource")
	if idx == -1 {
		return "", "", fmt.Errorf("invalid object ID format: expected /nonresource")
	}
	
	clusterID := rest[:idx]
	path := rest[idx+len("/nonresource"):]
	
	return clusterID, path, nil
}


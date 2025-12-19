package mapper

import (
	"fmt"
	"strings"
	
	authzv1 "k8s.io/api/authorization/v1"
	
	"github.com/kumarabd/policy-sdk-go/policy"
)

const (
	// MaxExtraKeys limits the number of extra keys to include in subject attributes
	MaxExtraKeys = 10
	
	// MaxExtraValuesPerKey limits the number of values per extra key
	MaxExtraValuesPerKey = 10
)

// mapSubjectFromSpec converts Kubernetes SubjectAccessReviewSpec user fields into a policy EntityRef.
func (m *Mapper) mapSubjectFromSpec(spec authzv1.SubjectAccessReviewSpec) (policy.EntityRef, error) {
	// Determine subject ID
	subjectID := ""
	if m.cfg.SubjectIDMode == "uid" && spec.UID != "" {
		subjectID = spec.UID
	} else {
		if spec.User == "" {
			return policy.EntityRef{}, fmt.Errorf("user is required when uid is not available")
		}
		subjectID = spec.User
	}
	
	// Build attributes
	attrs := make(map[string]string)
	
	if m.cfg.IncludeGroupsAsAttrs && len(spec.Groups) > 0 {
		// Join groups into a comma-separated string
		attrs["groups"] = strings.Join(spec.Groups, ",")
	}
	
	// Include extra fields (with size limits)
	// Note: authzv1.ExtraValue is []string, so we can use it directly
	if spec.Extra != nil && len(spec.Extra) > 0 {
		extraIncluded := 0
		for key, values := range spec.Extra {
			if extraIncluded >= MaxExtraKeys {
				// Note truncation in attributes
				attrs["_extra_truncated"] = "true"
				break
			}
			
			// Limit values per key
			valueCount := len(values)
			if valueCount > MaxExtraValuesPerKey {
				valueCount = MaxExtraValuesPerKey
			}
			
			// Join values
			valueStr := strings.Join(values[:valueCount], ",")
			if len(values) > MaxExtraValuesPerKey {
				valueStr += " (truncated)"
			}
			
			attrs[fmt.Sprintf("extra.%s", key)] = valueStr
			extraIncluded++
		}
	}
	
	return policy.EntityRef{
		ID:         subjectID,
		Type:       "SUBJECT",
		Attributes: attrs,
	}, nil
}

// mapResourceAction converts authzv1.ResourceAttributes into an action string.
func (m *Mapper) mapResourceAction(ra *authzv1.ResourceAttributes) string {
	verb := strings.ToLower(ra.Verb)
	resource := ra.Resource
	
	if m.cfg.ActionMode == "k8s.<verb>.<group>.<resource>" {
		// Include API group if non-empty
		group := ra.Group
		if group == "" {
			group = "core"
		}
		return fmt.Sprintf("k8s.%s.%s.%s", verb, group, resource)
	}
	
	// Default: k8s.<verb>.<resource>
	action := fmt.Sprintf("k8s.%s.%s", verb, resource)
	
	// Append subresource if present
	if ra.Subresource != "" {
		action += "/" + ra.Subresource
	}
	
	return action
}

// mapNonResourceAction converts authzv1.NonResourceAttributes into an action string.
func (m *Mapper) mapNonResourceAction(nra *authzv1.NonResourceAttributes) string {
	verb := strings.ToLower(nra.Verb)
	return fmt.Sprintf("k8s.%s.nonresource", verb)
}

// mapResourceObject converts authzv1.ResourceAttributes into a policy EntityRef.
func (m *Mapper) mapResourceObject(ra *authzv1.ResourceAttributes) policy.EntityRef {
	// Build canonical Kubernetes URI
	// Format: k8s://{clusterID}/ns/{namespace or _cluster}/{group or core}/{resource}/{name or _all}/{subresource or ""}
	
	parts := []string{"k8s://", m.cfg.ClusterID, "/ns/"}
	
	// Namespace
	namespace := ra.Namespace
	if namespace == "" {
		namespace = "_cluster" // Cluster-scoped resource
	}
	parts = append(parts, namespace, "/")
	
	// API Group
	group := ra.Group
	if group == "" {
		group = "core"
	}
	parts = append(parts, group, "/")
	
	// Resource
	parts = append(parts, ra.Resource, "/")
	
	// Name
	name := ra.Name
	if name == "" {
		name = "_all" // Collection operation
	}
	parts = append(parts, name)
	
	// Subresource
	if ra.Subresource != "" {
		parts = append(parts, "/", ra.Subresource)
	}
	
	objectID := strings.Join(parts, "")
	
	return policy.EntityRef{
		ID:   objectID,
		Type: "OBJECT",
	}
}

// mapNonResourceObject converts authzv1.NonResourceAttributes into a policy EntityRef.
func (m *Mapper) mapNonResourceObject(nra *authzv1.NonResourceAttributes) policy.EntityRef {
	// Format: k8s://{clusterID}/nonresource{path}
	path := nra.Path
	if path == "" {
		path = "/"
	}
	
	// Ensure path starts with /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	
	objectID := fmt.Sprintf("k8s://%s/nonresource%s", m.cfg.ClusterID, path)
	
	return policy.EntityRef{
		ID:   objectID,
		Type: "OBJECT",
	}
}

// mapResourceContext builds context map from authzv1.ResourceAttributes.
func (m *Mapper) mapResourceContext(ra *authzv1.ResourceAttributes, requestURI string) map[string]interface{} {
	ctx := make(map[string]interface{})
	
	ctx["verb"] = ra.Verb
	ctx["apiGroup"] = ra.Group
	if ra.Group == "" {
		ctx["apiGroup"] = "core"
	}
	ctx["version"] = ra.Version
	ctx["resource"] = ra.Resource
	if ra.Subresource != "" {
		ctx["subresource"] = ra.Subresource
	}
	if ra.Namespace != "" {
		ctx["namespace"] = ra.Namespace
	}
	if ra.Name != "" {
		ctx["name"] = ra.Name
	}
	if requestURI != "" {
		ctx["requestURI"] = requestURI
	}
	
	return ctx
}

// mapNonResourceContext builds context map from authzv1.NonResourceAttributes.
func (m *Mapper) mapNonResourceContext(nra *authzv1.NonResourceAttributes, requestURI string) map[string]interface{} {
	ctx := make(map[string]interface{})
	
	ctx["verb"] = nra.Verb
	ctx["path"] = nra.Path
	if requestURI != "" {
		ctx["requestURI"] = requestURI
	}
	
	return ctx
}


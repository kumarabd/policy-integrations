package mapper

import (
	"context"
	"fmt"

	authzv1 "k8s.io/api/authorization/v1"

	"github.com/kumarabd/policy-sdk-go/policy"
	"github.com/kumarabd/policy-sdk-go/runtime"
)

// Config configures the Kubernetes mapper behavior.
type Config struct {
	// ClusterID is a required, stable identifier for the Kubernetes cluster
	// (e.g., "clusterA", "dev-cluster", "prod-us-east-1")
	ClusterID string

	// TenantID is an optional default tenant ID if not provided by the caller
	TenantID string

	// SubjectIDMode determines how to construct the subject ID:
	// - "uid": use User.UID if available, fallback to Username
	// - "username": use Username (default)
	SubjectIDMode string

	// IncludeGroupsAsAttrs determines whether to include user groups in subject attributes
	// Default: true
	IncludeGroupsAsAttrs bool

	// ActionMode determines the action format:
	// - "k8s.<verb>.<resource>": default format (e.g., "k8s.get.pods")
	// - "k8s.<verb>.<group>.<resource>": include API group if non-empty (e.g., "k8s.get.apps.deployments")
	ActionMode string

	// ObjectIDMode determines the object ID format:
	// - "canonical": use canonical Kubernetes URI format (default)
	ObjectIDMode string
}

// DefaultConfig returns a default configuration with sensible defaults.
func DefaultConfig(clusterID string) Config {
	return Config{
		ClusterID:            clusterID,
		SubjectIDMode:        "username",
		IncludeGroupsAsAttrs: true,
		ActionMode:           "k8s.<verb>.<resource>",
		ObjectIDMode:         "canonical",
	}
}

// Mapper converts Kubernetes authorization requests into SDK policy requests.
// It implements the SDK's generic mapper interface.
type Mapper struct {
	cfg Config
}

// New creates a new Kubernetes mapper with the given configuration.
func New(cfg Config) (*Mapper, error) {
	if cfg.ClusterID == "" {
		return nil, fmt.Errorf("clusterID is required")
	}

	// Set defaults
	if cfg.SubjectIDMode == "" {
		cfg.SubjectIDMode = "username"
	}
	if cfg.ActionMode == "" {
		cfg.ActionMode = "k8s.<verb>.<resource>"
	}
	if cfg.ObjectIDMode == "" {
		cfg.ObjectIDMode = "canonical"
	}

	return &Mapper{
		cfg: cfg,
	}, nil
}

// Map converts a Kubernetes authorization request into a SDK policy request.
// It implements the SDK's mapper.Mapper interface.
// The requestURI parameter is optional and provides additional context about the original request.
func (m *Mapper) Map(ctx context.Context, spec authzv1.SubjectAccessReviewSpec, requestURI string) (policy.PolicyRequest, error) {
	// Validate input
	if err := m.validate(spec); err != nil {
		return policy.PolicyRequest{}, err
	}

	// Map subject from spec fields
	subject, err := m.mapSubjectFromSpec(spec)
	if err != nil {
		return policy.PolicyRequest{}, fmt.Errorf("failed to map subject: %w", err)
	}

	// Map action and object
	var action string
	var object policy.EntityRef
	var contextMap map[string]interface{}

	if spec.ResourceAttributes != nil {
		action = m.mapResourceAction(spec.ResourceAttributes)
		object = m.mapResourceObject(spec.ResourceAttributes)
		contextMap = m.mapResourceContext(spec.ResourceAttributes, requestURI)
	} else if spec.NonResourceAttributes != nil {
		action = m.mapNonResourceAction(spec.NonResourceAttributes)
		object = m.mapNonResourceObject(spec.NonResourceAttributes)
		contextMap = m.mapNonResourceContext(spec.NonResourceAttributes, requestURI)
	} else {
		// This should not happen due to validation, but handle it anyway
		return policy.PolicyRequest{}, fmt.Errorf("neither resourceAttributes nor nonResourceAttributes is set")
	}

	// Add cluster to context
	if contextMap == nil {
		contextMap = make(map[string]interface{})
	}
	contextMap["cluster"] = m.cfg.ClusterID

	// Build policy request
	req := policy.PolicyRequest{
		Subject: subject,
		Object:  object,
		Action:  action,
		Context: contextMap,
	}

	// Set tenant if configured
	if m.cfg.TenantID != "" {
		if req.Context == nil {
			req.Context = make(map[string]interface{})
		}
		req.Context["tenant"] = m.cfg.TenantID
	}

	return req, nil
}

// validate checks that the authorization request spec is valid.
func (m *Mapper) validate(spec authzv1.SubjectAccessReviewSpec) error {
	// Check user
	if spec.User == "" && spec.UID == "" {
		return runtime.BadRequest("INVALID_USER", "user and uid cannot both be empty", nil)
	}

	// Check that exactly one of resourceAttributes or nonResourceAttributes is set
	hasResource := spec.ResourceAttributes != nil
	hasNonResource := spec.NonResourceAttributes != nil

	if !hasResource && !hasNonResource {
		return runtime.BadRequest("INVALID_REQUEST", "either resourceAttributes or nonResourceAttributes must be set", nil)
	}

	if hasResource && hasNonResource {
		return runtime.BadRequest("INVALID_REQUEST", "resourceAttributes and nonResourceAttributes cannot both be set", nil)
	}

	// Check verb
	if hasResource {
		if spec.ResourceAttributes.Verb == "" {
			return runtime.BadRequest("INVALID_VERB", "verb is required in resourceAttributes", nil)
		}
	}

	if hasNonResource {
		if spec.NonResourceAttributes.Verb == "" {
			return runtime.BadRequest("INVALID_VERB", "verb is required in nonResourceAttributes", nil)
		}
	}

	return nil
}

package seeder

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/kumarabd/policy-integrations/pkg/k8s/conventions"
)

// RBACBinding represents a simplified RBAC binding for import.
// It combines a RoleBinding/ClusterRoleBinding with its referenced Role/ClusterRole rules.
type RBACBinding struct {
	// Name of the binding
	Name string `json:"name"`

	// Subjects in the binding (using official Kubernetes types)
	Subjects []rbacv1.Subject `json:"subjects"`

	// Role reference (using official Kubernetes types)
	RoleRef rbacv1.RoleRef `json:"roleRef"`

	// Rules from the referenced role (using official Kubernetes types)
	Rules []rbacv1.PolicyRule `json:"rules"`
}

// ImportRBACFromJSON imports RBAC bindings from a JSON file.
func (s *Seeder) ImportRBACFromJSON(ctx context.Context, filePath string, mode SeedMode, dryRun bool) (*SeedResult, error) {
	// Read JSON file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read RBAC file: %w", err)
	}

	var input struct {
		Bindings []RBACBinding `json:"bindings"`
	}

	if err := json.Unmarshal(data, &input); err != nil {
		return nil, fmt.Errorf("failed to parse RBAC JSON: %w", err)
	}

	result := &SeedResult{}

	// Process each binding
	for _, binding := range input.Bindings {
		// Create subject set for binding subjects
		subjectSetName := fmt.Sprintf("k8s:binding:%s", binding.Name)
		subjectSetID, err := s.createSubjectSetFromRBAC(ctx, subjectSetName, binding.Subjects, mode, dryRun)
		if err != nil {
			return nil, fmt.Errorf("failed to create subject set for binding %s: %w", binding.Name, err)
		}
		if subjectSetID != "" {
			result.CreatedSubjectSets++
		}

		// Create object sets and rules for each rule
		for _, rule := range binding.Rules {
			// Handle resource rules
			for _, apiGroup := range rule.APIGroups {
				for _, resource := range rule.Resources {
					for _, verb := range rule.Verbs {
						// Build object set name
						objectSetName := fmt.Sprintf("k8s:rule:%s:%s:%s", apiGroup, resource, verb)
						if apiGroup == "" {
							apiGroup = "core"
						}

						// Build object ID (collection for now)
						objectID := conventions.BuildResourceObjectID(s.clusterID, "", apiGroup, resource, "", "")

						// Create object set
						objectSetID, err := s.createObjectSetWithMode(ctx, objectSetName, "", objectID, mode, dryRun)
						if err != nil {
							return nil, fmt.Errorf("failed to create object set: %w", err)
						}
						if objectSetID != "" {
							result.CreatedObjectSets++
						}

						// Build action
						action := conventions.BuildResourceAction(verb, apiGroup, resource, "", conventions.ActionModeSimple)

						// Create rule
						ruleName := fmt.Sprintf("k8s:rbac:%s:%s", binding.Name, objectSetName)
						ruleID, err := s.createRuleWithMode(ctx, ruleName, subjectSetID, objectSetID, []string{action}, mode, dryRun)
						if err != nil {
							return nil, fmt.Errorf("failed to create rule: %w", err)
						}
						if ruleID != "" {
							result.CreatedRules++
						}
					}
				}
			}

			// Handle non-resource URLs
			for _, url := range rule.NonResourceURLs {
				for _, verb := range rule.Verbs {
					// Build object set for non-resource
					objectSetName := fmt.Sprintf("k8s:nonresource:%s", url)
					objectID := conventions.BuildNonResourceObjectID(s.clusterID, url)

					objectSetID, err := s.createObjectSetWithMode(ctx, objectSetName, "", objectID, mode, dryRun)
					if err != nil {
						return nil, fmt.Errorf("failed to create object set: %w", err)
					}
					if objectSetID != "" {
						result.CreatedObjectSets++
					}

					// Build action
					action := conventions.BuildNonResourceAction(verb)

					// Create rule
					ruleName := fmt.Sprintf("k8s:rbac:%s:nonresource:%s", binding.Name, url)
					ruleID, err := s.createRuleWithMode(ctx, ruleName, subjectSetID, objectSetID, []string{action}, mode, dryRun)
					if err != nil {
						return nil, fmt.Errorf("failed to create rule: %w", err)
					}
					if ruleID != "" {
						result.CreatedRules++
					}
				}
			}
		}
	}

	return result, nil
}

// createSubjectSetFromRBAC creates a subject set from RBAC subjects.
func (s *Seeder) createSubjectSetFromRBAC(ctx context.Context, name string, subjects []rbacv1.Subject, mode SeedMode, dryRun bool) (string, error) {
	if dryRun {
		fmt.Printf("[DRY-RUN] Would create subject set: %s with %d subjects\n", name, len(subjects))
		return name, nil
	}

	// Check if exists
	if mode == SeedModeMerge {
		exists, err := s.subjectSetExists(ctx, name)
		if err == nil && exists {
			fmt.Printf("Subject set %s already exists, skipping\n", name)
			return "", nil // Return empty to indicate no creation
		}
	}

	// Create subject set
	id, err := s.createSubjectSet(ctx, name, fmt.Sprintf("Imported from RBAC (%d subjects)", len(subjects)))
	if err != nil {
		return "", err
	}

	// TODO: Add subjects to the set using AddSubjectSetMembers endpoint
	// For now, just create the empty set

	return id, nil
}

// createObjectSetWithMode is a wrapper that handles mode and dry-run.
func (s *Seeder) createObjectSetWithMode(ctx context.Context, name, description, objectID string, mode SeedMode, dryRun bool) (string, error) {
	if dryRun {
		fmt.Printf("[DRY-RUN] Would create object set: %s\n", name)
		return name, nil
	}

	// Check if exists
	if mode == SeedModeMerge {
		exists, err := s.objectSetExists(ctx, name)
		if err == nil && exists {
			fmt.Printf("Object set %s already exists, skipping\n", name)
			return "", nil // Return empty to indicate no creation
		}
	}

	return s.createObjectSet(ctx, name, description, objectID)
}

// createRuleWithMode is a wrapper that handles mode and dry-run.
func (s *Seeder) createRuleWithMode(ctx context.Context, name, subjectSetID, objectSetID string, actions []string, mode SeedMode, dryRun bool) (string, error) {
	if dryRun {
		fmt.Printf("[DRY-RUN] Would create rule: %s\n", name)
		return name, nil
	}

	// Check if exists
	if mode == SeedModeMerge {
		exists, err := s.ruleExists(ctx, name)
		if err == nil && exists {
			fmt.Printf("Rule %s already exists, skipping\n", name)
			return "", nil // Return empty to indicate no creation
		}
	}

	return s.createRule(ctx, name, subjectSetID, objectSetID, actions)
}

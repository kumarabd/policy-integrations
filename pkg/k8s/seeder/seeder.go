package seeder

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/kumarabd/policy-integrations/pkg/k8s/conventions"
)

// Seeder handles policy seeding operations.
type Seeder struct {
	baseURL    string
	tenant     string
	clusterID  string
	httpClient *http.Client
}

// NewSeeder creates a new seeder instance.
func NewSeeder(baseURL, tenant, clusterID string) *Seeder {
	return &Seeder{
		baseURL:   baseURL,
		tenant:    tenant,
		clusterID: clusterID,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SeedMode determines the seeding behavior.
type SeedMode string

const (
	// SeedModeBootstrap creates a fresh policy setup
	SeedModeBootstrap SeedMode = "bootstrap"
	// SeedModeMerge merges with existing policy (idempotent)
	SeedModeMerge SeedMode = "merge"
)

// SeedResult contains the results of a seeding operation.
type SeedResult struct {
	CreatedSubjectSets int
	CreatedObjectSets  int
	CreatedRules       int
	CreatedDenies      int
	UpdatedEntities    int
	Revision           int64
	VersionID          string
}

// SeedFromRBAC seeds policy from RBAC JSON file.
func (s *Seeder) SeedFromRBAC(ctx context.Context, filePath string, mode SeedMode, dryRun bool) (*SeedResult, error) {
	return s.ImportRBACFromJSON(ctx, filePath, mode, dryRun)
}

// Seed creates baseline Kubernetes policy.
func (s *Seeder) Seed(ctx context.Context, mode SeedMode, dryRun bool) (*SeedResult, error) {
	result := &SeedResult{}

	// Create common subject sets
	subjectSets, err := s.createCommonSubjectSets(ctx, mode, dryRun)
	if err != nil {
		return nil, fmt.Errorf("failed to create subject sets: %w", err)
	}
	result.CreatedSubjectSets = len(subjectSets)

	// Create common object sets
	objectSets, err := s.createCommonObjectSets(ctx, mode, dryRun)
	if err != nil {
		return nil, fmt.Errorf("failed to create object sets: %w", err)
	}
	result.CreatedObjectSets = len(objectSets)

	// Create baseline rules
	rules, err := s.createBaselineRules(ctx, subjectSets, objectSets, mode, dryRun)
	if err != nil {
		return nil, fmt.Errorf("failed to create rules: %w", err)
	}
	result.CreatedRules = len(rules)

	// Get current revision
	if !dryRun {
		rev, versionID, err := s.getCurrentRevision(ctx)
		if err == nil {
			result.Revision = rev
			result.VersionID = versionID
		}
	}

	return result, nil
}

// createCommonSubjectSets creates common Kubernetes subject sets.
func (s *Seeder) createCommonSubjectSets(ctx context.Context, mode SeedMode, dryRun bool) ([]string, error) {
	sets := []struct {
		name        string
		description string
	}{
		{"k8s:cluster-admins", "Kubernetes cluster administrators"},
		{"k8s:cluster-readers", "Kubernetes cluster readers"},
		{"k8s:namespace-creators", "Users who can create namespaces"},
	}

	var created []string
	for _, set := range sets {
		if dryRun {
			fmt.Printf("[DRY-RUN] Would create subject set: %s\n", set.name)
			created = append(created, set.name)
			continue
		}

		// Check if exists (merge mode)
		if mode == SeedModeMerge {
			exists, err := s.subjectSetExists(ctx, set.name)
			if err == nil && exists {
				fmt.Printf("Subject set %s already exists, skipping\n", set.name)
				continue
			}
		}

		id, err := s.createSubjectSet(ctx, set.name, set.description)
		if err != nil {
			return nil, fmt.Errorf("failed to create subject set %s: %w", set.name, err)
		}
		created = append(created, id)
		fmt.Printf("Created subject set: %s (id: %s)\n", set.name, id)
	}

	return created, nil
}

// createCommonObjectSets creates common Kubernetes object sets.
func (s *Seeder) createCommonObjectSets(ctx context.Context, mode SeedMode, dryRun bool) (map[string]string, error) {
	// Object sets for common resources
	sets := []struct {
		name        string
		description string
		objectID    string
	}{
		{"k8s:cluster-scoped:all", "All cluster-scoped resources", s.buildObjectID("", "", "", "", "")},
		{"k8s:core:pods:all", "All pods", s.buildObjectID("default", "core", "pods", "", "")},
		{"k8s:core:services:all", "All services", s.buildObjectID("default", "core", "services", "", "")},
		{"k8s:apps:deployments:all", "All deployments", s.buildObjectID("default", "apps", "deployments", "", "")},
		{"k8s:nonresource:api", "Kubernetes API endpoints", conventions.BuildNonResourceObjectID(s.clusterID, "/api")},
		{"k8s:nonresource:healthz", "Health check endpoints", conventions.BuildNonResourceObjectID(s.clusterID, "/healthz")},
	}

	created := make(map[string]string)
	for _, set := range sets {
		if dryRun {
			fmt.Printf("[DRY-RUN] Would create object set: %s\n", set.name)
			created[set.name] = set.name
			continue
		}

		// Check if exists (merge mode)
		if mode == SeedModeMerge {
			exists, err := s.objectSetExists(ctx, set.name)
			if err == nil && exists {
				fmt.Printf("Object set %s already exists, skipping\n", set.name)
				continue
			}
		}

		id, err := s.createObjectSet(ctx, set.name, set.description, set.objectID)
		if err != nil {
			return nil, fmt.Errorf("failed to create object set %s: %w", set.name, err)
		}
		created[set.name] = id
		fmt.Printf("Created object set: %s (id: %s)\n", set.name, id)
	}

	return created, nil
}

// createBaselineRules creates baseline allow rules.
func (s *Seeder) createBaselineRules(ctx context.Context, subjectSets []string, objectSets map[string]string, mode SeedMode, dryRun bool) ([]string, error) {
	// Example: cluster-admins can do everything
	// This is simplified - in practice, you'd create more granular rules

	if len(subjectSets) == 0 || len(objectSets) == 0 {
		return nil, nil
	}

	rules := []struct {
		name         string
		subjectSetID string
		objectSetID  string
		actions      []string
	}{
		{
			name:         "cluster-admins-full-access",
			subjectSetID: subjectSets[0], // k8s:cluster-admins
			objectSetID:  objectSets["k8s:cluster-scoped:all"],
			actions:      []string{"k8s.get", "k8s.list", "k8s.watch", "k8s.create", "k8s.update", "k8s.patch", "k8s.delete"},
		},
	}

	var created []string
	for _, rule := range rules {
		if dryRun {
			fmt.Printf("[DRY-RUN] Would create rule: %s\n", rule.name)
			created = append(created, rule.name)
			continue
		}

		// Check if exists (merge mode)
		if mode == SeedModeMerge {
			exists, err := s.ruleExists(ctx, rule.name)
			if err == nil && exists {
				fmt.Printf("Rule %s already exists, skipping\n", rule.name)
				continue
			}
		}

		id, err := s.createRule(ctx, rule.name, rule.subjectSetID, rule.objectSetID, rule.actions)
		if err != nil {
			return nil, fmt.Errorf("failed to create rule %s: %w", rule.name, err)
		}
		created = append(created, id)
		fmt.Printf("Created rule: %s (id: %s)\n", rule.name, id)
	}

	return created, nil
}

// Helper methods for API calls

func (s *Seeder) buildObjectID(namespace, group, resource, name, subresource string) string {
	return conventions.BuildResourceObjectID(s.clusterID, namespace, group, resource, name, subresource)
}

func (s *Seeder) makeRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	url := fmt.Sprintf("%s%s", s.baseURL, path)

	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewReader(jsonData)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-Id", s.tenant)

	return s.httpClient.Do(req)
}

func (s *Seeder) createSubjectSet(ctx context.Context, name, description string) (string, error) {
	body := map[string]interface{}{
		"name": name,
	}

	resp, err := s.makeRequest(ctx, "POST", "/api/v1/subject-sets", body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create subject set: status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var result struct {
		Group struct {
			ID string `json:"id"`
		} `json:"group"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if result.Group.ID != "" {
		return result.Group.ID, nil
	}

	return "", fmt.Errorf("no ID in response")
}

func (s *Seeder) subjectSetExists(ctx context.Context, name string) (bool, error) {
	resp, err := s.makeRequest(ctx, "GET", fmt.Sprintf("/api/v1/subject-sets?query=%s", name), nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var result struct {
		Groups []struct {
			Name string `json:"name"`
		} `json:"groups"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	for _, group := range result.Groups {
		if group.Name == name {
			return true, nil
		}
	}

	return false, nil
}

func (s *Seeder) createObjectSet(ctx context.Context, name, description, objectID string) (string, error) {
	// First create the object if it doesn't exist
	objectIDUUID, err := s.ensureObject(ctx, objectID)
	if err != nil {
		return "", fmt.Errorf("failed to ensure object: %w", err)
	}

	// Create object set with the object
	body := map[string]interface{}{
		"name": name,
		"objects": []map[string]interface{}{
			{
				"type": "object",
				"id":   objectIDUUID,
			},
		},
	}

	resp, err := s.makeRequest(ctx, "POST", "/api/v1/object-sets", body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create object set: status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var result struct {
		Group struct {
			ID string `json:"id"`
		} `json:"group"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if result.Group.ID != "" {
		return result.Group.ID, nil
	}

	return "", fmt.Errorf("no ID in response")
}

// ensureObject ensures an object exists and returns its UUID.
func (s *Seeder) ensureObject(ctx context.Context, externalID string) (string, error) {
	// Check if object exists
	resp, err := s.makeRequest(ctx, "GET", fmt.Sprintf("/api/v1/objects?query=%s", externalID), nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var result struct {
			Objects []struct {
				ID         string `json:"id"`
				ExternalID string `json:"external_id"`
			} `json:"objects"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			for _, obj := range result.Objects {
				if obj.ExternalID == externalID {
					return obj.ID, nil
				}
			}
		}
	}

	// Create object
	body := map[string]interface{}{
		"external_id": externalID,
	}

	resp, err = s.makeRequest(ctx, "POST", "/api/v1/objects", body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create object: status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var result struct {
		Object struct {
			ID string `json:"id"`
		} `json:"object"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if result.Object.ID != "" {
		return result.Object.ID, nil
	}

	return "", fmt.Errorf("no ID in response")
}

func (s *Seeder) objectSetExists(ctx context.Context, name string) (bool, error) {
	resp, err := s.makeRequest(ctx, "GET", fmt.Sprintf("/api/v1/object-sets?query=%s", name), nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var result struct {
		Groups []struct {
			Name string `json:"name"`
		} `json:"groups"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	for _, group := range result.Groups {
		if group.Name == name {
			return true, nil
		}
	}

	return false, nil
}

func (s *Seeder) createRule(ctx context.Context, name, subjectSetID, objectSetID string, actions []string) (string, error) {
	body := map[string]interface{}{
		"name": name,
		"subjectSelector": map[string]interface{}{
			"type": "subject-set",
			"id":   subjectSetID,
		},
		"objectSelector": map[string]interface{}{
			"type": "object-set",
			"id":   objectSetID,
		},
		"actions": actions,
	}

	resp, err := s.makeRequest(ctx, "POST", "/api/v1/rules", body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create rule: status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var result struct {
		Rule struct {
			ID string `json:"id"`
		} `json:"rule"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if result.Rule.ID != "" {
		return result.Rule.ID, nil
	}

	return "", fmt.Errorf("no ID in response")
}

func (s *Seeder) ruleExists(ctx context.Context, name string) (bool, error) {
	resp, err := s.makeRequest(ctx, "GET", fmt.Sprintf("/api/v1/rules?query=%s", name), nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var result struct {
		Rules []struct {
			Name string `json:"name"`
		} `json:"rules"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	for _, rule := range result.Rules {
		if rule.Name == name {
			return true, nil
		}
	}

	return false, nil
}

func (s *Seeder) getCurrentRevision(ctx context.Context) (int64, string, error) {
	resp, err := s.makeRequest(ctx, "GET", "/api/v1/revisions/current", nil)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("failed to get revision: status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, "", err
	}

	revision := int64(0)
	if r, ok := result["revision"].(float64); ok {
		revision = int64(r)
	}

	versionID := ""
	if v, ok := result["version_id"].(string); ok {
		versionID = v
	} else if revision > 0 {
		versionID = fmt.Sprintf("rev:%d", revision)
	}

	return revision, versionID, nil
}

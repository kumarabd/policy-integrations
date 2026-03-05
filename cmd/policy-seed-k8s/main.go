package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kumarabd/policy-sdk-go/client"
	"github.com/kumarabd/policy-sdk-go/policy"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	var (
		pdpBaseURL = flag.String("pdp-base-url", "http://localhost:8501", "Base URL of the policy-machine controlplane")
		tenant     = flag.String("tenant", "", "Tenant ID (required)")
		clusterID  = flag.String("cluster-id", "", "Cluster ID (required, used in object IDs and attributes)")
		kubeconfig = flag.String("kubeconfig", "", "Path to kubeconfig (defaults to in-cluster or ~/.kube/config)")
	)
	flag.Parse()

	if *tenant == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --tenant is required")
		os.Exit(1)
	}
	if *clusterID == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --cluster-id is required")
		os.Exit(1)
	}

	// Build Kubernetes client
	cfg, err := buildKubeConfig(*kubeconfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to build kubeconfig: %v\n", err)
		os.Exit(1)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to create kube client: %v\n", err)
		os.Exit(1)
	}

	// Build RBAC client
	rbacClient := client.NewHTTPControlPlaneClient(client.HTTPControlPlaneConfig{
		BaseURL: *pdpBaseURL,
		Timeout: 30 * time.Second,
	})

	// Seed objects
	ctx := policy.WithTenant(context.Background(), *tenant)
	if err := seedObjects(ctx, cs, rbacClient, *clusterID); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: seeding objects failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Object seeding completed successfully")

	// Seed subjects (users, groups, serviceaccounts)
	if err := seedSubjects(ctx, cs, rbacClient); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: seeding subjects failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Subject seeding completed successfully")

	// Seed roles and clusterroles as RBAC roles
	if err := seedRoles(ctx, cs, rbacClient); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: seeding roles failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Role seeding completed successfully")

	// Seed bindings (RoleBindings and ClusterRoleBindings)
	if err := seedBindings(ctx, cs, rbacClient); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: seeding bindings failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Binding seeding completed successfully")
}

// buildKubeConfig builds a rest.Config from either a kubeconfig path or in-cluster config.
func buildKubeConfig(path string) (*rest.Config, error) {
	if path != "" {
		return clientcmd.BuildConfigFromFlags("", path)
	}
	// Try in-cluster, then default kubeconfig path
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	if home, err := os.UserHomeDir(); err == nil {
		kubeconfig := home + "/.kube/config"
		if _, err := os.Stat(kubeconfig); err == nil {
			return clientcmd.BuildConfigFromFlags("", kubeconfig)
		}
	}
	return nil, fmt.Errorf("could not find valid kubeconfig or in-cluster config")
}

// seedObjects scans a subset of Kubernetes resources and pushes them as RBAC objects.
func seedObjects(ctx context.Context, cs *kubernetes.Clientset, rbacClient *client.HTTPControlPlaneClient, clusterID string) error {
	var objects []client.RBACObject

	// Pods (core/v1)
	pods, err := cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err == nil {
		fmt.Printf("Discovered %d Pods\n", len(pods.Items))
		for _, pod := range pods.Items {
			if shouldSkipObjectKind(pod.Kind) {
				continue
			}
			obj := buildRBACObject(clusterID, pod.APIVersion, pod.Kind, pod.Namespace, pod.Name, pod.Labels)
			objects = append(objects, obj)
		}
	} else {
		fmt.Fprintf(os.Stderr, "WARN: listing Pods failed: %v\n", err)
	}

	// Services (core/v1)
	services, err := cs.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err == nil {
		fmt.Printf("Discovered %d Services\n", len(services.Items))
		for _, svc := range services.Items {
			if shouldSkipObjectKind(svc.Kind) {
				continue
			}
			obj := buildRBACObject(clusterID, svc.APIVersion, svc.Kind, svc.Namespace, svc.Name, svc.Labels)
			objects = append(objects, obj)
		}
	} else {
		fmt.Fprintf(os.Stderr, "WARN: listing Services failed: %v\n", err)
	}

	// ConfigMaps (core/v1)
	configMaps, err := cs.CoreV1().ConfigMaps("").List(ctx, metav1.ListOptions{})
	if err == nil {
		fmt.Printf("Discovered %d ConfigMaps\n", len(configMaps.Items))
		for _, cm := range configMaps.Items {
			if shouldSkipObjectKind(cm.Kind) {
				continue
			}
			obj := buildRBACObject(clusterID, cm.APIVersion, cm.Kind, cm.Namespace, cm.Name, cm.Labels)
			objects = append(objects, obj)
		}
	} else {
		fmt.Fprintf(os.Stderr, "WARN: listing ConfigMaps failed: %v\n", err)
	}

	// Namespaces (core/v1, cluster-scoped)
	namespaces, err := cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err == nil {
		fmt.Printf("Discovered %d Namespaces\n", len(namespaces.Items))
		for _, ns := range namespaces.Items {
			if shouldSkipObjectKind(ns.Kind) {
				continue
			}
			obj := buildRBACObject(clusterID, ns.APIVersion, ns.Kind, "", ns.Name, ns.Labels)
			objects = append(objects, obj)
		}
	} else {
		fmt.Fprintf(os.Stderr, "WARN: listing Namespaces failed: %v\n", err)
	}

	// TODO: add more resource kinds (Deployments, StatefulSets, DaemonSets, etc.)

	fmt.Printf("Total Kubernetes objects to seed: %d\n", len(objects))

	// Batch upsert in chunks
	const batchSize = 100
	for i := 0; i < len(objects); i += batchSize {
		end := i + batchSize
		if end > len(objects) {
			end = len(objects)
		}
		batch := objects[i:end]
		fmt.Printf("Seeding objects batch %d-%d (size=%d)\n", i, end, len(batch))
		req := client.RBACUpsertObjectsRequest{Objects: batch}
		if err := rbacClient.RBACUpsertObjects(ctx, req); err != nil {
			return fmt.Errorf("RBACUpsertObjects batch %d-%d failed: %w", i, end, err)
		}
	}

	return nil
}

// shouldSkipObjectKind returns true for K8s "types" we don't want to import as objects.
func shouldSkipObjectKind(kind string) bool {
	k := strings.ToLower(kind)
	switch k {
	case "user", "serviceaccount", "group", "role", "rolebinding", "clusterrole", "clusterrolebinding":
		return true
	default:
		return false
	}
}

// seedSubjects imports Kubernetes users, groups, and serviceaccounts as RBAC subjects.
// Name: subject name; Kind: user/group/serviceaccount; Metadata: namespace, apiversion, apigroup, labels.
func seedSubjects(ctx context.Context, cs *kubernetes.Clientset, rbacClient *client.HTTPControlPlaneClient) error {
	seen := make(map[string]struct{}) // key: kind|namespace|name
	var subjects []client.RBACSubject

	// Helper to stage a subject once
	upsert := func(kind, namespace, name, apiVersion, apiGroup string, labels map[string]string) error {
		if name == "" {
			return nil
		}
		key := fmt.Sprintf("%s|%s|%s", kind, namespace, name)
		if _, ok := seen[key]; ok {
			return nil
		}
		seen[key] = struct{}{}

		meta := map[string]string{
			"kind":      kind,
			"apigroup":  apiGroup,
			"apiversion": apiVersion,
		}
		if namespace != "" {
			meta["namespace"] = namespace
		}
		for k, v := range labels {
			if k == "" || v == "" {
				continue
			}
			meta[k] = v
		}

		subj := client.RBACSubject{
			Name:     name,
			Kind:     kind,
			Metadata: meta,
		}

		subjects = append(subjects, subj)
		return nil
	}

	// ServiceAccounts from the API (core/v1)
	serviceAccounts, err := cs.CoreV1().ServiceAccounts("").List(ctx, metav1.ListOptions{})
	if err == nil {
		fmt.Printf("Discovered %d ServiceAccounts\n", len(serviceAccounts.Items))
		for _, sa := range serviceAccounts.Items {
			group, _ := splitAPIVersion(sa.APIVersion)
			if err := upsert("serviceaccount", sa.Namespace, sa.Name, sa.APIVersion, group, sa.Labels); err != nil {
				return err
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "WARN: listing ServiceAccounts failed: %v\n", err)
	}

	fmt.Printf("Total RBAC subjects to seed: %d\n", len(subjects))

	// Batch upsert subjects in chunks via RBACUpsertSubjects.
	const batchSize = 100
	for i := 0; i < len(subjects); i += batchSize {
		end := i + batchSize
		if end > len(subjects) {
			end = len(subjects)
		}
		batch := subjects[i:end]
		fmt.Printf("Seeding subjects batch %d-%d (size=%d)\n", i, end, len(batch))
		req := client.RBACUpsertSubjectsRequest{Subjects: batch}
		if err := rbacClient.RBACUpsertSubjects(ctx, req); err != nil {
			return fmt.Errorf("RBACUpsertSubjects batch %d-%d failed: %w", i, end, err)
		}
	}

	return nil
}

// seedRoles imports Kubernetes Roles and ClusterRoles as RBAC roles (subject attributes).
// For each rule in a Role/ClusterRole:
// - Creates an assignment from the role to the apiGroup attribute (e.g. "discovery.k8s.io").
// - Creates an assignment from the role to the resource attribute (e.g. "endpointslices").
// The assignment's actions are the verbs (list, watch, get, etc). Existing assignments are
// extended with any missing verbs by the controlplane via CreateAssociationForAttributes.
func seedRoles(ctx context.Context, cs *kubernetes.Clientset, rbacClient *client.HTTPControlPlaneClient) error {
	var roles []client.RBACRole

	// Namespaced Roles
	roleList, err := cs.RbacV1().Roles("").List(ctx, metav1.ListOptions{})
	if err == nil {
		fmt.Printf("Discovered %d Roles\n", len(roleList.Items))
		for _, r := range roleList.Items {
			perms := buildPermissionsFromPolicyRules(r.Rules)
			if len(perms) == 0 {
				continue
			}
			name := r.Namespace + "/" + r.Name
			roles = append(roles, client.RBACRole{
				Name:        name,
				Description: "Role " + name,
				Permissions: perms,
			})
		}
	} else {
		fmt.Fprintf(os.Stderr, "WARN: listing Roles failed: %v\n", err)
	}

	// ClusterRoles
	clusterRoleList, err := cs.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err == nil {
		fmt.Printf("Discovered %d ClusterRoles\n", len(clusterRoleList.Items))
		for _, cr := range clusterRoleList.Items {
			perms := buildPermissionsFromPolicyRules(cr.Rules)
			if len(perms) == 0 {
				continue
			}
			name := "clusterrole/" + cr.Name
			roles = append(roles, client.RBACRole{
				Name:        name,
				Description: "ClusterRole " + cr.Name,
				Permissions: perms,
			})
		}
	} else {
		fmt.Fprintf(os.Stderr, "WARN: listing ClusterRoles failed: %v\n", err)
	}

	fmt.Printf("Total RBAC roles to seed: %d\n", len(roles))

	// Batch upsert roles via RBACUpsertRoles.
	const batchSize = 50
	for i := 0; i < len(roles); i += batchSize {
		end := i + batchSize
		if end > len(roles) {
			end = len(roles)
		}
		batch := roles[i:end]
		fmt.Printf("Seeding roles batch %d-%d (size=%d)\n", i, end, len(batch))
		req := client.RBACUpsertRolesRequest{Roles: batch}
		if err := rbacClient.RBACUpsertRoles(ctx, req); err != nil {
			return fmt.Errorf("RBACUpsertRoles batch %d-%d failed: %w", i, end, err)
		}
	}

	return nil
}

// seedBindings imports Kubernetes RoleBindings and ClusterRoleBindings as RBAC bindings.
// A binding connects a list of subjects to a role (subject attribute).
func seedBindings(ctx context.Context, cs *kubernetes.Clientset, rbacClient *client.HTTPControlPlaneClient) error {
	byRole := make(map[string]map[string]struct{}) // roleName -> set(subjectName)

	// Namespaced RoleBindings
	roleBindings, err := cs.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	if err == nil {
		fmt.Printf("Discovered %d RoleBindings\n", len(roleBindings.Items))
		for _, rb := range roleBindings.Items {
			roleName := ""
			switch rb.RoleRef.Kind {
			case "Role":
				roleName = rb.Namespace + "/" + rb.RoleRef.Name
			case "ClusterRole":
				roleName = "clusterrole/" + rb.RoleRef.Name
			default:
				continue
			}
			if roleName == "" {
				continue
			}
			subjectsSet, ok := byRole[roleName]
			if !ok {
				subjectsSet = make(map[string]struct{})
				byRole[roleName] = subjectsSet
			}
			for _, s := range rb.Subjects {
				if s.Name == "" {
					continue
				}
				// Use the raw subject name; subjects are keyed by ExternalID=name in the controlplane.
				subjectsSet[s.Name] = struct{}{}
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "WARN: listing RoleBindings failed: %v\n", err)
	}

	// ClusterRoleBindings
	clusterRoleBindings, err := cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err == nil {
		fmt.Printf("Discovered %d ClusterRoleBindings\n", len(clusterRoleBindings.Items))
		for _, crb := range clusterRoleBindings.Items {
			roleName := ""
			if crb.RoleRef.Kind == "ClusterRole" {
				roleName = "clusterrole/" + crb.RoleRef.Name
			} else if crb.RoleRef.Kind == "Role" {
				// Rare, but handle defensively
				roleName = crb.RoleRef.Name
			}
			if roleName == "" {
				continue
			}
			subjectsSet, ok := byRole[roleName]
			if !ok {
				subjectsSet = make(map[string]struct{})
				byRole[roleName] = subjectsSet
			}
			for _, s := range crb.Subjects {
				if s.Name == "" {
					continue
				}
				subjectsSet[s.Name] = struct{}{}
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "WARN: listing ClusterRoleBindings failed: %v\n", err)
	}

	// Build binding payloads
	var bindings []client.RBACBindingByName
	for roleName, subjectsSet := range byRole {
		var subjectNames []string
		for name := range subjectsSet {
			subjectNames = append(subjectNames, name)
		}
		if len(subjectNames) == 0 {
			continue
		}
		bindings = append(bindings, client.RBACBindingByName{
			RoleName:     roleName,
			SubjectNames: subjectNames,
		})
	}

	fmt.Printf("Total RBAC bindings to seed: %d\n", len(bindings))

	// Batch upsert bindings via RBACUpsertBindings.
	const batchSize = 50
	for i := 0; i < len(bindings); i += batchSize {
		end := i + batchSize
		if end > len(bindings) {
			end = len(bindings)
		}
		batch := bindings[i:end]
		fmt.Printf("Seeding bindings batch %d-%d (size=%d)\n", i, end, len(batch))
		req := client.RBACUpsertBindingsRequest{Bindings: batch}
		if err := rbacClient.RBACUpsertBindings(ctx, req); err != nil {
			return fmt.Errorf("RBACUpsertBindings batch %d-%d failed: %w", i, end, err)
		}
	}

	return nil
}

// buildPermissionsFromPolicyRules flattens Kubernetes PolicyRules into RBAC permissions.
// For each rule:
// - For each apiGroup, create permissions for each verb with objectAttribute = apiGroup (or "core" if empty).
// - For each resource, create permissions for each verb with objectAttribute = resource name.
func buildPermissionsFromPolicyRules(rules []rbacv1.PolicyRule) []client.RBACPermission {
	var perms []client.RBACPermission

	for _, rule := range rules {
		if len(rule.Verbs) == 0 {
			continue
		}

		// apiGroups -> object attributes
		for _, group := range rule.APIGroups {
			attr := group
			if attr == "" {
				attr = "core"
			}
			for _, verb := range rule.Verbs {
				if verb == "" {
					continue
				}
				perms = append(perms, client.RBACPermission{
					Action:          verb,
					ObjectAttribute: attr,
				})
			}
		}

		// resources -> object attributes
		for _, res := range rule.Resources {
			if res == "" {
				continue
			}
			for _, verb := range rule.Verbs {
				if verb == "" {
					continue
				}
				perms = append(perms, client.RBACPermission{
					Action:          verb,
					ObjectAttribute: res,
				})
			}
		}
	}

	return perms
}

// buildRBACObject constructs a canonical RBAC object and its attributes.
// Name is a stable, cluster-scoped URI; attributes encode kind, group, version, namespace, and labels.
func buildRBACObject(clusterID, apiVersion, kind, namespace, name string, labels map[string]string) client.RBACObject {
	group, _ := splitAPIVersion(apiVersion)

	// Canonical object ID
	scope := "cluster"
	if namespace != "" {
		scope = "ns/" + namespace
	}
	objectID := fmt.Sprintf("k8s://%s/%s/%s/%s/%s", clusterID, scope, apiVersion, kind, name)

	attrs := map[string]string{
		"kind":       kind,
		"apiversion": apiVersion,
		"apigroup":   group,
		"cluster":    clusterID,
	}
	if namespace != "" {
		attrs["namespace"] = namespace
	}
	for k, v := range labels {
		if k == "" || v == "" {
			continue
		}
		attrs[k] = v
	}

	return client.RBACObject{
		ID:         objectID,
		Name:       objectID,
		Kind:       kind,
		Metadata:   map[string]string{"cluster": clusterID},
		Attributes: attrs,
	}
}

// splitAPIVersion splits apiVersion into group and version.
// "v1" -> ("core", "v1"), "apps/v1" -> ("apps", "v1").
func splitAPIVersion(apiVersion string) (string, string) {
	if apiVersion == "" {
		return "core", ""
	}
	for i := 0; i < len(apiVersion); i++ {
		if apiVersion[i] == '/' {
			return apiVersion[:i], apiVersion[i+1:]
		}
	}
	return "core", apiVersion
}

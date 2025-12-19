package main

import (
	"context"
	"fmt"
	"os"
	"time"
	
	authzv1 "k8s.io/api/authorization/v1"
	
	"github.com/kumarabd/policy-integrations/pkg/k8s/mapper"
	"github.com/kumarabd/policy-sdk-go/cache"
	"github.com/kumarabd/policy-sdk-go/client"
	"github.com/kumarabd/policy-sdk-go/config"
	"github.com/kumarabd/policy-sdk-go/policy"
	"github.com/kumarabd/policy-sdk-go/runtime"
	"github.com/kumarabd/policy-sdk-go/runtime/version"
	"github.com/kumarabd/policy-sdk-go/telemetry"
)

// This example demonstrates how to use the Kubernetes mapper with the PEP SDK.
// It shows:
// - Building the SDK components (HTTP PDP client, version provider, cache, telemetry)
// - Creating a Kubernetes mapper
// - Converting a Kubernetes authorization request to a policy request
// - Making a policy decision using the SDK
func main() {
	// 1. Create SDK configuration
	cfg := config.Default()
	cfg.DefaultTenant = "tenant-123"
	cfg.FailMode = "fail_closed"
	cfg.ExplainEnabled = true
	cfg.CacheMaxEntries = 50000
	cfg.CacheTTL = 30 * time.Second
	cfg.VersionRefreshInterval = 2 * time.Second
	
	// 2. Build HTTP PDP client
	pdpClient := client.NewHTTPClient(client.HTTPClientConfig{
		BaseURL:      "http://localhost:8500",
		EvaluatePath: "/api/v1/evaluate",
		Timeout:      10 * time.Second,
		StaticHeaders: map[string]string{
			// Add Authorization header if needed
			// "Authorization": "Bearer <token>",
		},
	})
	
	// 3. Build version provider (HTTP + cached)
	httpVersionProvider := version.NewHTTPProvider(version.HTTPProviderConfig{
		BaseURL: "http://localhost:8500",
		Path:    "/api/v1/revisions/current",
		Timeout: 5 * time.Second,
	})
	cachedVersionProvider := version.NewCachedProvider(httpVersionProvider, cfg.VersionRefreshInterval)
	
	// 4. Build decision cache
	decisionCache := cache.NewLRUCache(
		cfg.CacheMaxEntries,
		cfg.CacheTTL,
		cache.WithOnEvent(func(event cache.CacheEvent) {
			// Optional: emit metrics for cache events
			fmt.Printf("Cache event: %s (key: %s, size: %d)\n", event.Type, event.Key, event.Size)
		}),
	)
	
	// 5. Build telemetry (JSON logger)
	logger := telemetry.NewJSONLogger(os.Stdout, "info")
	
	// 6. Create SDK instance
	sdk := runtime.New(
		cfg,
		pdpClient,
		decisionCache,
		logger,
		runtime.WithVersionProvider(cachedVersionProvider),
	)
	
	// 7. Create Kubernetes mapper
	k8sMapper, err := mapper.New(mapper.Config{
		ClusterID:            "dev-cluster",
		TenantID:             "tenant-123",
		SubjectIDMode:        "username",
		IncludeGroupsAsAttrs: true,
		ActionMode:           "k8s.<verb>.<resource>",
		ObjectIDMode:         "canonical",
	})
	if err != nil {
		fmt.Printf("Failed to create mapper: %v\n", err)
		os.Exit(1)
	}
	
	// 8. Create a Kubernetes authorization request using official types
	spec := authzv1.SubjectAccessReviewSpec{
		User:   "alice",
		UID:    "user-123",
		Groups: []string{"devs", "engineers"},
		Extra: map[string]authzv1.ExtraValue{
			"authn.kubernetes.io/username": {"alice"},
		},
		ResourceAttributes: &authzv1.ResourceAttributes{
			Verb:      "get",
			Resource:  "pods",
			Namespace: "default",
			Name:      "nginx",
		},
	}
	requestURI := "/api/v1/namespaces/default/pods/nginx"
	
	// 9. Add tenant to context
	ctx := policy.WithTenant(context.Background(), "tenant-123")
	
	// 10. Map Kubernetes request to policy request
	policyReq, err := k8sMapper.Map(ctx, spec, requestURI)
	if err != nil {
		fmt.Printf("Failed to map request: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Printf("Mapped policy request:\n")
	fmt.Printf("  Subject: %s (type: %s)\n", policyReq.Subject.ID, policyReq.Subject.Type)
	fmt.Printf("  Object: %s (type: %s)\n", policyReq.Object.ID, policyReq.Object.Type)
	fmt.Printf("  Action: %s\n", policyReq.Action)
	fmt.Printf("  Context keys: %v\n", getContextKeys(policyReq.Context))
	
	// 11. Make a policy decision
	result, err := sdk.Decide(ctx, policyReq)
	if err != nil {
		fmt.Printf("Error making decision: %v\n", err)
		os.Exit(1)
	}
	
	// 12. Use the result
	fmt.Printf("\nDecision Result:\n")
	fmt.Printf("  Allowed: %v\n", result.Allowed)
	fmt.Printf("  Reason: %s\n", result.Reason)
	fmt.Printf("  Version ID: %s\n", result.VersionID)
	if result.CacheInfo != nil {
		fmt.Printf("  Cache Hit: %v\n", result.CacheInfo.Hit)
	}
	
	if result.Allowed {
		fmt.Printf("\n✅ Access GRANTED\n")
	} else {
		fmt.Printf("\n❌ Access DENIED\n")
	}
	
	// 13. Example: Explain (if enabled)
	if cfg.ExplainEnabled {
		fmt.Printf("\n--- Explain Request ---\n")
		explainResult, err := sdk.Explain(ctx, policyReq)
		if err != nil {
			fmt.Printf("Explain error: %v\n", err)
		} else {
			fmt.Printf("Explain decision: %s\n", explainResult.Reason)
			if explainResult.Trace != nil {
				fmt.Printf("Trace available: %v\n", len(explainResult.Trace) > 0)
			}
		}
	}
}

// getContextKeys returns the keys from a context map for display purposes.
func getContextKeys(ctx map[string]interface{}) []string {
	if ctx == nil {
		return nil
	}
	keys := make([]string, 0, len(ctx))
	for k := range ctx {
		keys = append(keys, k)
	}
	return keys
}


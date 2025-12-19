package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/kumarabd/policy-integrations/pkg/k8s/seeder"
)

func main() {
	var (
		pdpBaseURL = flag.String("pdp-base-url", "http://localhost:8500", "Base URL of the PDP control plane")
		tenant     = flag.String("tenant", "", "Tenant ID (required)")
		clusterID  = flag.String("cluster-id", "", "Cluster ID (required)")
		mode       = flag.String("mode", "merge", "Seed mode: bootstrap or merge")
		fromRBAC   = flag.String("from-rbac-yaml", "", "Path to Kubernetes RBAC YAML file (optional)")
		dryRun     = flag.Bool("dry-run", false, "Dry run mode (don't apply changes)")
		debug      = flag.Bool("debug", false, "Enable debug logging")
	)

	flag.Parse()

	// Validate required flags
	if *tenant == "" {
		fmt.Fprintf(os.Stderr, "Error: --tenant is required\n")
		os.Exit(1)
	}

	if *clusterID == "" {
		fmt.Fprintf(os.Stderr, "Error: --cluster-id is required\n")
		os.Exit(1)
	}

	// Validate mode
	seedMode := seeder.SeedMode(*mode)
	if seedMode != seeder.SeedModeBootstrap && seedMode != seeder.SeedModeMerge {
		fmt.Fprintf(os.Stderr, "Error: --mode must be 'bootstrap' or 'merge'\n")
		os.Exit(1)
	}

	if *debug {
		fmt.Printf("Debug mode enabled\n")
		fmt.Printf("PDP Base URL: %s\n", *pdpBaseURL)
		fmt.Printf("Tenant: %s\n", *tenant)
		fmt.Printf("Cluster ID: %s\n", *clusterID)
		fmt.Printf("Mode: %s\n", *mode)
		fmt.Printf("Dry Run: %v\n", *dryRun)
	}

	// Create seeder
	seed := seeder.NewSeeder(*pdpBaseURL, *tenant, *clusterID)

	// Handle RBAC import if specified
	ctx := context.Background()
	var result *seeder.SeedResult
	var err error

	if *fromRBAC != "" {
		// Import from RBAC JSON file
		result, err = seed.SeedFromRBAC(ctx, *fromRBAC, seedMode, *dryRun)
	} else {
		// Run baseline seeding
		result, err = seed.Seed(ctx, seedMode, *dryRun)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error seeding policy: %v\n", err)
		os.Exit(1)
	}

	// Print summary
	fmt.Printf("\n=== Seeding Summary ===\n")
	if *dryRun {
		fmt.Printf("Mode: DRY RUN (no changes applied)\n")
	} else {
		fmt.Printf("Mode: %s\n", *mode)
	}
	fmt.Printf("Created Subject Sets: %d\n", result.CreatedSubjectSets)
	fmt.Printf("Created Object Sets: %d\n", result.CreatedObjectSets)
	fmt.Printf("Created Rules: %d\n", result.CreatedRules)
	fmt.Printf("Created Denies: %d\n", result.CreatedDenies)

	if result.Revision > 0 {
		fmt.Printf("Policy Revision: %d\n", result.Revision)
	}
	if result.VersionID != "" {
		fmt.Printf("Policy Version ID: %s\n", result.VersionID)
	}

	fmt.Printf("\nSeeding completed successfully!\n")
}

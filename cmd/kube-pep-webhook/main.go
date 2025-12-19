package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	
	"github.com/kumarabd/policy-integrations/pkg/k8s/webhook"
)

func main() {
	// Allow config file override (optional)
	configFile := flag.String("config", "", "Path to config file (not implemented, using env vars)")
	flag.Parse()
	
	if *configFile != "" {
		log.Printf("Config file specified: %s (not implemented, using environment variables)", *configFile)
	}
	
	// Load configuration from environment
	cfg := webhook.LoadFromEnv()
	
	// Create and start server
	server, err := webhook.NewServer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create server: %v\n", err)
		os.Exit(1)
	}
	
	// Start server (blocks until shutdown)
	if err := server.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}


package webhook

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kumarabd/policy-integrations/pkg/k8s/mapper"
	"github.com/kumarabd/policy-sdk-go/cache"
	"github.com/kumarabd/policy-sdk-go/client"
	"github.com/kumarabd/policy-sdk-go/config"
	"github.com/kumarabd/policy-sdk-go/runtime"
	"github.com/kumarabd/policy-sdk-go/runtime/version"
	"github.com/kumarabd/policy-sdk-go/telemetry"
)

// Server wraps the HTTP server and dependencies.
type Server struct {
	httpServer *http.Server
	config     Config
}

// NewServer creates and initializes a new webhook server.
func NewServer(cfg Config) (*Server, error) {
	// Validate config
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Build telemetry (JSON logger to stdout)
	logger := telemetry.NewJSONLogger(os.Stdout, "info")

	// Build PDP HTTP client
	pdpClient := client.NewHTTPClient(client.HTTPClientConfig{
		BaseURL:       cfg.PDPBaseURL,
		EvaluatePath:  cfg.PDPEvaluatePath,
		Timeout:       cfg.PDPTimeout,
		TenantHeader:  cfg.TenantHeader,
		StaticHeaders: map[string]string{
			// Add Authorization header if configured via env var
			// "Authorization": os.Getenv("PDP_AUTH_TOKEN"),
		},
	})

	// Build version provider
	httpVersionProvider := version.NewHTTPProvider(version.HTTPProviderConfig{
		BaseURL:      cfg.PDPBaseURL,
		Path:         "/api/v1/revisions/current",
		Timeout:      cfg.PDPTimeout,
		TenantHeader: cfg.TenantHeader,
	})
	cachedVersionProvider := version.NewCachedProvider(httpVersionProvider, cfg.VersionRefreshInterval)

	// Build decision cache with telemetry hook
	decisionCache := cache.NewLRUCache(
		cfg.SDKCacheMaxEntries,
		cfg.SDKCacheTTL,
		cache.WithOnEvent(func(event cache.CacheEvent) {
			// Emit telemetry for cache events
			logger.IncCounter(telemetry.MetricCacheEventsTotal, telemetry.Labels(
				telemetry.LabelTenant, cfg.TenantID,
				"type", string(event.Type),
			), 1)
		}),
	)

	// Build SDK config
	sdkConfig := config.Default()
	sdkConfig.DefaultTenant = cfg.TenantID
	sdkConfig.FailMode = cfg.FailMode
	sdkConfig.ExplainEnabled = cfg.ExplainEnabled
	sdkConfig.CacheMaxEntries = cfg.SDKCacheMaxEntries
	sdkConfig.CacheTTL = cfg.SDKCacheTTL
	sdkConfig.VersionRefreshInterval = cfg.VersionRefreshInterval

	// Create SDK
	sdk := runtime.New(
		sdkConfig,
		pdpClient,
		decisionCache,
		logger,
		runtime.WithVersionProvider(cachedVersionProvider),
	)

	// Build Kubernetes mapper
	mapperConfig := mapper.Config{
		ClusterID:            cfg.ClusterID,
		TenantID:             cfg.TenantID,
		SubjectIDMode:        cfg.SubjectIDMode,
		IncludeGroupsAsAttrs: true,
		ActionMode:           cfg.ActionMode,
		ObjectIDMode:         "canonical",
	}
	k8sMapper, err := mapper.New(mapperConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create mapper: %w", err)
	}

	// Create circuit breaker
	breakerConfig := DefaultBreakerConfig()
	breakerConfig.OnStateChange = func(from, to BreakerState) {
		logger.Info("circuit breaker state change", telemetry.Fields(
			"from", from.String(),
			"to", to.String(),
		))
	}
	breaker := NewBreaker(breakerConfig)

	// Create metrics
	metrics := NewMetrics()

	// Create webhook handler
	webhookHandler := NewHandler(sdk, k8sMapper, breaker, metrics, cfg)

	// Setup routes
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", webhookHandler.Authorize)
	mux.HandleFunc("/healthz", webhookHandler.Healthz)
	mux.HandleFunc("/readyz", webhookHandler.Readyz)
	mux.HandleFunc("/metrics", webhookHandler.Metrics)
	mux.HandleFunc("/debug/cache", webhookHandler.DebugCache)

	// Apply middleware
	handler := requestIDMiddleware(mux)
	handler = timeoutMiddleware(cfg.RequestTimeout)(handler)
	handler = accessLogMiddleware(handler)

	// Create HTTP server
	httpServer := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return &Server{
		httpServer: httpServer,
		config:     cfg,
	}, nil
}

// Start starts the webhook server with TLS.
func (s *Server) Start() error {
	// Load TLS certificate
	cert, err := tls.LoadX509KeyPair(s.config.TLSCertFile, s.config.TLSKeyFile)
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Configure client certificate verification
	if s.config.TLSClientCAFile != "" && !s.config.InsecureSkipClientVerify {
		// Load CA certificate
		caCert, err := os.ReadFile(s.config.TLSClientCAFile)
		if err != nil {
			return fmt.Errorf("failed to load client CA certificate: %w", err)
		}

		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return fmt.Errorf("failed to parse client CA certificate")
		}

		tlsConfig.ClientCAs = caPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	} else if s.config.InsecureSkipClientVerify {
		log.Printf("WARNING: Client certificate verification is disabled. This should only be used for local development!")
	}

	s.httpServer.TLSConfig = tlsConfig

	log.Printf("Starting PEP webhook server on %s", s.config.ListenAddr)

	// Start server in goroutine
	go func() {
		if err := s.httpServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown error: %w", err)
	}

	log.Println("Server stopped")
	return nil
}

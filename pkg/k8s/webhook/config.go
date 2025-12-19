package webhook

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds the webhook server configuration.
type Config struct {
	// ListenAddr is the address to listen on (default: ":8443")
	ListenAddr string

	// TLSCertFile is the path to the TLS certificate file (required in production)
	TLSCertFile string

	// TLSKeyFile is the path to the TLS private key file (required in production)
	TLSKeyFile string

	// PDPBaseURL is the base URL of the Policy Decision Point (required)
	PDPBaseURL string

	// PDPEvaluatePath is the path for evaluation requests (default: "/api/v1/evaluate")
	PDPEvaluatePath string

	// TenantID is the default tenant ID if not provided by header
	TenantID string

	// TenantHeader is the header name for tenant ID (default: "X-Tenant-Id")
	TenantHeader string

	// ClusterID is the Kubernetes cluster identifier (required)
	ClusterID string

	// SubjectIDMode determines subject ID format ("username" or "uid", default: "username")
	SubjectIDMode string

	// ActionMode determines action format ("simple" or "with_group", default: "simple")
	ActionMode string

	// FailMode determines failure behavior ("fail_closed" or "fail_open", default: "fail_closed")
	FailMode string

	// ExplainEnabled enables explain mode (default: false)
	ExplainEnabled bool

	// DebugToken is required for explain mode (security check)
	DebugToken string

	// SDKCacheMaxEntries is the maximum number of cache entries (default: 50000)
	SDKCacheMaxEntries int

	// SDKCacheTTL is the cache TTL duration (default: 10s)
	SDKCacheTTL time.Duration

	// VersionRefreshInterval is the version refresh interval (default: 2s)
	VersionRefreshInterval time.Duration

	// PDPTimeout is the timeout for PDP requests (default: 100ms)
	PDPTimeout time.Duration

	// RequestTimeout is the timeout for webhook handler end-to-end (default: 200ms)
	RequestTimeout time.Duration

	// ExplainMaxBytes limits the size of explain trace logs (default: 16KB)
	ExplainMaxBytes int

	// TLSClientCAFile is the path to the CA certificate file for client cert verification
	TLSClientCAFile string

	// InsecureSkipClientVerify allows skipping client cert verification (dev only)
	InsecureSkipClientVerify bool

	// MaxRequestSize is the maximum request body size in bytes (default: 1MB)
	MaxRequestSize int64

	// DebugClientCNs is a comma-separated list of allowed client cert CNs for debug mode
	DebugClientCNs string
}

// LoadFromEnv loads configuration from environment variables.
func LoadFromEnv() Config {
	cfg := Config{
		ListenAddr:               getEnv("LISTEN_ADDR", ":8443"),
		TLSCertFile:              os.Getenv("TLS_CERT_FILE"),
		TLSKeyFile:               os.Getenv("TLS_KEY_FILE"),
		PDPBaseURL:               os.Getenv("PDP_BASE_URL"),
		PDPEvaluatePath:          getEnv("PDP_EVALUATE_PATH", "/api/v1/evaluate"),
		TenantID:                 os.Getenv("TENANT_ID"),
		TenantHeader:             getEnv("TENANT_HEADER", "X-Tenant-Id"),
		ClusterID:                os.Getenv("CLUSTER_ID"),
		SubjectIDMode:            getEnv("SUBJECT_ID_MODE", "username"),
		ActionMode:               getEnv("ACTION_MODE", "simple"),
		FailMode:                 getEnv("FAIL_MODE", "fail_closed"),
		ExplainEnabled:           getEnvBool("EXPLAIN_ENABLED", false),
		DebugToken:               os.Getenv("DEBUG_TOKEN"),
		SDKCacheMaxEntries:       getEnvInt("SDK_CACHE_MAX_ENTRIES", 50000),
		SDKCacheTTL:              getEnvDuration("SDK_CACHE_TTL", 10*time.Second),
		VersionRefreshInterval:   getEnvDuration("VERSION_REFRESH_INTERVAL", 2*time.Second),
		PDPTimeout:               getEnvDuration("PDP_TIMEOUT", 100*time.Millisecond),
		RequestTimeout:           getEnvDuration("REQUEST_TIMEOUT", 200*time.Millisecond),
		ExplainMaxBytes:          getEnvInt("EXPLAIN_MAX_BYTES", 16*1024),
		TLSClientCAFile:          os.Getenv("TLS_CLIENT_CA_FILE"),
		InsecureSkipClientVerify: getEnvBool("INSECURE_SKIP_CLIENT_VERIFY", false),
		MaxRequestSize:           getEnvInt64("MAX_REQUEST_SIZE", 1024*1024), // 1MB
		DebugClientCNs:           os.Getenv("DEBUG_CLIENT_CNS"),
	}

	// Map action mode
	if cfg.ActionMode == "simple" {
		cfg.ActionMode = "k8s.<verb>.<resource>"
	} else if cfg.ActionMode == "with_group" {
		cfg.ActionMode = "k8s.<verb>.<group>.<resource>"
	}

	return cfg
}

// Validate checks that required configuration is present and valid.
func (c *Config) Validate() error {
	if c.PDPBaseURL == "" {
		return &ConfigError{Field: "PDP_BASE_URL", Message: "PDP_BASE_URL is required"}
	}
	if c.ClusterID == "" {
		return &ConfigError{Field: "CLUSTER_ID", Message: "CLUSTER_ID is required"}
	}
	if c.TLSCertFile == "" || c.TLSKeyFile == "" {
		return &ConfigError{Field: "TLS_CERT_FILE/TLS_KEY_FILE", Message: "TLS certificate and key files are required"}
	}

	// Validate timeouts
	if c.PDPTimeout >= c.RequestTimeout {
		return &ConfigError{Field: "PDP_TIMEOUT/REQUEST_TIMEOUT", Message: "PDP_TIMEOUT must be less than REQUEST_TIMEOUT"}
	}

	// Warn about insecure mode
	if c.InsecureSkipClientVerify {
		fmt.Fprintf(os.Stderr, "WARNING: INSECURE_SKIP_CLIENT_VERIFY is enabled. This should only be used for local development!\n")
	}

	// Warn about cache TTL vs version refresh
	if c.SDKCacheTTL < c.VersionRefreshInterval {
		fmt.Fprintf(os.Stderr, "WARNING: SDK_CACHE_TTL (%v) is less than VERSION_REFRESH_INTERVAL (%v). This may cause cache invalidation issues.\n",
			c.SDKCacheTTL, c.VersionRefreshInterval)
	}
	if c.SDKCacheTTL > 60*time.Second {
		fmt.Fprintf(os.Stderr, "WARNING: SDK_CACHE_TTL (%v) is greater than 60s. This may be too large for authorization decisions.\n", c.SDKCacheTTL)
	}

	return nil
}

// ConfigError represents a configuration validation error.
type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return e.Message
}

// Helper functions for environment variable parsing

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return defaultValue
}

func getEnvInt64(key string, defaultValue int64) int64 {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			return i
		}
	}
	return defaultValue
}

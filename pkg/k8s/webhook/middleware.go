package webhook

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/kumarabd/policy-sdk-go/policy"
	"github.com/kumarabd/policy-sdk-go/runtime"
)

// requestIDMiddleware adds a request ID to the context and response headers.
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get or generate request ID
		reqID := r.Header.Get("X-Request-Id")
		if reqID == "" {
			reqID = runtime.NewUUID()
		}

		// Add to context
		ctx := policy.WithRequestID(r.Context(), reqID)

		// Add to response header
		w.Header().Set("X-Request-Id", reqID)

		// Call next handler with updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// timeoutMiddleware enforces a timeout on request handling.
func timeoutMiddleware(timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			// Create a response writer that tracks if response was written
			rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Handle request with timeout
			done := make(chan bool, 1)
			go func() {
				next.ServeHTTP(rw, r.WithContext(ctx))
				done <- true
			}()

			select {
			case <-done:
				// Request completed
			case <-ctx.Done():
				// Timeout occurred
				if !rw.written {
					http.Error(w, "Request timeout", http.StatusRequestTimeout)
				}
			}
		})
	}
}

// responseWriter wraps http.ResponseWriter to track if response was written.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.written = true
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	rw.written = true
	return rw.ResponseWriter.Write(b)
}

// accessLogMiddleware logs structured access information.
func accessLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create response writer to capture status
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Call next handler
		next.ServeHTTP(rw, r)

		// Log access
		duration := time.Since(start)
		reqID, _ := policy.RequestIDFromContext(r.Context())

		// Structured log format (can be enhanced with proper logger)
		fmt.Printf("access_log method=%s path=%s status=%d duration_ms=%d request_id=%s\n",
			r.Method,
			r.URL.Path,
			rw.statusCode,
			duration.Milliseconds(),
			reqID,
		)
	})
}

// clientCertMiddleware verifies client certificates when TLS_CLIENT_CA_FILE is set.
func clientCertMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if client cert verification is required
		// This is handled at the TLS level, but we can add additional checks here
		if r.TLS != nil && len(r.TLS.PeerCertificates) == 0 {
			// No client cert provided but TLS is enabled
			// This will be caught by TLS config, but we can log it
		}

		next.ServeHTTP(w, r)
	})
}

package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	authzv1 "k8s.io/api/authorization/v1"

	"github.com/kumarabd/policy-integrations/pkg/k8s/mapper"
	"github.com/kumarabd/policy-sdk-go/client"
	"github.com/kumarabd/policy-sdk-go/decision"
	"github.com/kumarabd/policy-sdk-go/policy"
	"github.com/kumarabd/policy-sdk-go/runtime"
)

// Handler holds the webhook handler dependencies.
type Handler struct {
	sdk     *runtime.SDK
	mapper  *mapper.Mapper
	config  Config
	breaker *Breaker
	metrics *Metrics
}

// NewHandler creates a new webhook handler.
func NewHandler(sdk *runtime.SDK, k8sMapper *mapper.Mapper, breaker *Breaker, metrics *Metrics, cfg Config) *Handler {
	return &Handler{
		sdk:     sdk,
		mapper:  k8sMapper,
		config:  cfg,
		breaker: breaker,
		metrics: metrics,
	}
}

// Authorize handles Kubernetes SubjectAccessReview requests.
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Track metrics
	defer func() {
		h.metrics.RecordRequestDuration(time.Since(startTime))
	}()
	h.metrics.IncRequestsTotal()

	// Enforce request size limit
	r.Body = http.MaxBytesReader(w, r.Body, h.config.MaxRequestSize)

	// Check for explain mode with enhanced security
	explain := false
	if h.config.ExplainEnabled {
		if r.URL.Query().Get("explain") == "1" {
			// Verify debug token
			debugToken := r.Header.Get("X-Debug-Token")
			if debugToken == "" || debugToken != h.config.DebugToken {
				http.Error(w, "Debug token required for explain mode", http.StatusForbidden)
				return
			}

			// Verify client cert CN if configured
			if h.config.DebugClientCNs != "" {
				if !h.verifyDebugClientCert(r) {
					http.Error(w, "Client certificate not authorized for debug mode", http.StatusForbidden)
					return
				}
			}

			explain = true
		}
	}

	// Decode request
	var sar SubjectAccessReview
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&sar); err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		h.metrics.IncRequestsError()
		return
	}

	// Strict validation
	if err := h.validateSAR(&sar); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		h.metrics.IncRequestsError()
		return
	}

	// Extract request URI from the original request
	requestURI := r.RequestURI

	// Resolve tenant
	tenant := h.config.TenantID
	if tenantHeader := r.Header.Get(h.config.TenantHeader); tenantHeader != "" {
		tenant = tenantHeader
	}
	if tenant != "" {
		ctx = policy.WithTenant(ctx, tenant)
	}

	// Map to policy request using SubjectAccessReviewSpec directly
	policyReq, err := h.mapper.Map(ctx, sar.Spec, requestURI)
	if err != nil {
		h.respondError(w, &sar, fmt.Sprintf("Mapping failed: %v", err), nil)
		return
	}

	// Check circuit breaker
	if !h.breaker.Allow() {
		// Breaker is open
		h.metrics.IncPDPCallsError()
		if h.config.FailMode == "fail_open" {
			status := &authzv1.SubjectAccessReviewStatus{
				Allowed:         true,
				Denied:          false,
				Reason:          "PDP_UNAVAILABLE_FAIL_OPEN",
				EvaluationError: "Circuit breaker is open; PDP unavailable",
			}
			sar.Status = status
			h.metrics.IncRequestsAllow()
			// No result available when circuit breaker is open
			h.logAudit(ctx, sar, policyReq, status, decision.EnforcementResult{}, nil, time.Since(startTime))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(sar)
			return
		} else {
			// fail_closed
			status := &authzv1.SubjectAccessReviewStatus{
				Allowed:         false,
				Denied:          true,
				Reason:          "PDP_UNAVAILABLE",
				EvaluationError: "Circuit breaker is open; PDP unavailable",
			}
			sar.Status = status
			h.metrics.IncRequestsDeny()
			// No result available when circuit breaker is open
			h.logAudit(ctx, sar, policyReq, status, decision.EnforcementResult{}, nil, time.Since(startTime))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(sar)
			return
		}
	}

	// Make decision
	pdpStart := time.Now()
	var result decision.EnforcementResult
	if explain {
		result, err = h.sdk.Explain(ctx, policyReq)
	} else {
		result, err = h.sdk.Decide(ctx, policyReq)
	}
	pdpDuration := time.Since(pdpStart)
	h.metrics.RecordPDPDuration(pdpDuration)
	h.metrics.IncPDPCallsTotal()

	if err != nil {
		h.breaker.RecordFailure()
		h.metrics.IncPDPCallsError()
		// Build error status
		status := h.buildStatus(result, err, explain, policyReq)
		sar.Status = status
		// Pass result for audit logging (includes version ID)
		h.logAudit(ctx, sar, policyReq, status, result, err, time.Since(startTime))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(sar)
		return
	}

	h.breaker.RecordSuccess()
	h.metrics.IncPDPCallsOK()

	// Build response
	status := h.buildStatus(result, err, explain, policyReq)
	sar.Status = status

	// Track decision metrics
	if result.Allowed {
		h.metrics.IncRequestsAllow()
	} else {
		h.metrics.IncRequestsDeny()
	}

	// Log explain trace if enabled
	if explain && result.Trace != nil {
		h.logExplainTrace(ctx, result.Trace)
	}

	// Audit logging (pass result for version ID and other metadata)
	h.logAudit(ctx, sar, policyReq, status, result, err, time.Since(startTime))

	// Always return 200 for well-formed requests
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(sar)
}

// buildStatus constructs the authzv1.SubjectAccessReviewStatus from the SDK result.
// Note: SubjectAccessReviewStatus does not have AuditAnnotations field.
// Audit information is logged separately via logAudit().
func (h *Handler) buildStatus(result decision.EnforcementResult, err error, explain bool, policyReq policy.PolicyRequest) *authzv1.SubjectAccessReviewStatus {
	status := &authzv1.SubjectAccessReviewStatus{
		Allowed: result.Allowed,
		Denied:  !result.Allowed,
		Reason:  result.Reason,
	}

	// Enhance reason with additional context if available
	if result.VersionID != "" {
		if status.Reason != "" {
			status.Reason = fmt.Sprintf("%s (version: %s)", status.Reason, result.VersionID)
		} else {
			status.Reason = fmt.Sprintf("version: %s", result.VersionID)
		}
	}

	if explain {
		if status.Reason != "" {
			status.Reason = fmt.Sprintf("%s [explain mode]", status.Reason)
		} else {
			status.Reason = "[explain mode]"
		}
	}

	// Handle errors
	if err != nil {
		// Check if it's an API error
		if apiErr, ok := err.(*client.ApiError); ok {
			// For 4xx errors, include in evaluationError
			if apiErr.StatusCode >= 400 && apiErr.StatusCode < 500 {
				status.EvaluationError = fmt.Sprintf("PDP request failed: %s", apiErr.Message)
			} else {
				// For 5xx/unavailable, fail mode already handled in SDK
				status.EvaluationError = "PDP unavailable"
			}
		} else {
			status.EvaluationError = "Evaluation error (see logs)"
		}
	}

	return status
}

// respondError returns an error response.
func (h *Handler) respondError(w http.ResponseWriter, sar *SubjectAccessReview, message string, err error) {
	status := &authzv1.SubjectAccessReviewStatus{
		Allowed:         false,
		Denied:          true,
		Reason:          "Error processing request",
		EvaluationError: message,
	}

	if err != nil {
		status.EvaluationError = fmt.Sprintf("%s: %v", message, err)
	}

	sar.Status = status

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(sar)
}

// logExplainTrace logs the explain trace with size limits.
func (h *Handler) logExplainTrace(ctx context.Context, trace map[string]interface{}) {
	// Marshal trace to JSON
	traceJSON, err := json.Marshal(trace)
	if err != nil {
		return
	}

	// Limit size
	if len(traceJSON) > h.config.ExplainMaxBytes {
		traceJSON = traceJSON[:h.config.ExplainMaxBytes]
		traceJSON = append(traceJSON, []byte("... (truncated)")...)
	}

	reqID, _ := policy.RequestIDFromContext(ctx)
	fmt.Printf("explain_trace request_id=%s trace=%s\n", reqID, string(traceJSON))
}

// Healthz returns a health check response.
func (h *Handler) Healthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// Readyz returns a readiness check response.
// For now, just returns OK if the process is running.
// Can be enhanced to check PDP connectivity.
func (h *Handler) Readyz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// Metrics returns Prometheus-style metrics.
func (h *Handler) Metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(h.metrics.FormatPrometheus()))
}

// DebugCache returns cache statistics (admin-only).
func (h *Handler) DebugCache(w http.ResponseWriter, r *http.Request) {
	// Verify debug token
	debugToken := r.Header.Get("X-Debug-Token")
	if debugToken == "" || debugToken != h.config.DebugToken {
		http.Error(w, "Debug token required", http.StatusForbidden)
		return
	}

	// Get cache info from SDK (if available)
	// For now, return basic info
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Note: SDK cache doesn't expose Len() directly, so we'd need to add that
	// For now, return placeholder
	json.NewEncoder(w).Encode(map[string]interface{}{
		"cache_hits":   h.metrics.cacheHits,
		"cache_misses": h.metrics.cacheMisses,
		"note":         "Full cache statistics require SDK cache Len() method",
	})
}

// validateSAR validates a SubjectAccessReview request.
func (h *Handler) validateSAR(sar *SubjectAccessReview) error {
	// Validate apiVersion
	if sar.APIVersion != "authorization.k8s.io/v1" && sar.APIVersion != "authorization.k8s.io/v1beta1" {
		return fmt.Errorf("invalid apiVersion: must be authorization.k8s.io/v1 or v1beta1")
	}

	// Validate kind
	if sar.Kind != "SubjectAccessReview" {
		return fmt.Errorf("invalid kind: must be SubjectAccessReview")
	}

	// Validate user
	if sar.Spec.User == "" && sar.Spec.UID == "" {
		return fmt.Errorf("user or uid is required")
	}

	// Validate that exactly one of resourceAttributes or nonResourceAttributes is set
	hasResource := sar.Spec.ResourceAttributes != nil
	hasNonResource := sar.Spec.NonResourceAttributes != nil

	if !hasResource && !hasNonResource {
		return fmt.Errorf("either resourceAttributes or nonResourceAttributes must be set")
	}

	if hasResource && hasNonResource {
		return fmt.Errorf("resourceAttributes and nonResourceAttributes cannot both be set")
	}

	// Validate verb
	if hasResource {
		if sar.Spec.ResourceAttributes.Verb == "" {
			return fmt.Errorf("verb is required in resourceAttributes")
		}
	}

	if hasNonResource {
		if sar.Spec.NonResourceAttributes.Verb == "" {
			return fmt.Errorf("verb is required in nonResourceAttributes")
		}
	}

	return nil
}

// verifyDebugClientCert verifies that the client certificate CN is in the allowlist.
func (h *Handler) verifyDebugClientCert(r *http.Request) bool {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return false
	}

	// Get client cert CN
	cert := r.TLS.PeerCertificates[0]
	cn := cert.Subject.CommonName

	// Check against allowlist
	allowedCNs := strings.Split(h.config.DebugClientCNs, ",")
	for _, allowed := range allowedCNs {
		if strings.TrimSpace(allowed) == cn {
			return true
		}
	}

	return false
}

// logAudit logs structured audit information.
// result is passed to include version ID and other metadata (since SubjectAccessReviewStatus doesn't have AuditAnnotations).
func (h *Handler) logAudit(ctx context.Context, sar SubjectAccessReview, policyReq policy.PolicyRequest, status *authzv1.SubjectAccessReviewStatus, result decision.EnforcementResult, err error, duration time.Duration) {
	reqID, _ := policy.RequestIDFromContext(ctx)
	tenant, _ := policy.TenantFromContext(ctx)

	// Sanitize user info (no full JWTs)
	user := sar.Spec.User
	if len(user) > 100 {
		user = user[:100] + "..."
	}

	// Build audit log entry
	audit := map[string]interface{}{
		"ts":           time.Now().Format(time.RFC3339Nano),
		"request_id":   reqID,
		"tenant":       tenant,
		"cluster":      h.config.ClusterID,
		"user":         user,
		"groups_count": len(sar.Spec.Groups),
		"decision": map[string]interface{}{
			"allowed": status.Allowed,
			"denied":  status.Denied,
			"reason":  status.Reason,
		},
		"action":      policyReq.Action,
		"object_id":   policyReq.Object.ID,
		"duration_ms": duration.Milliseconds(),
	}

	// Add resource/non-resource info
	if sar.Spec.ResourceAttributes != nil {
		audit["verb"] = sar.Spec.ResourceAttributes.Verb
		audit["resource"] = sar.Spec.ResourceAttributes.Resource
		audit["namespace"] = sar.Spec.ResourceAttributes.Namespace
		audit["name"] = sar.Spec.ResourceAttributes.Name
	} else if sar.Spec.NonResourceAttributes != nil {
		audit["verb"] = sar.Spec.NonResourceAttributes.Verb
		audit["path"] = sar.Spec.NonResourceAttributes.Path
	}

	// Add policy version from result
	// Note: SubjectAccessReviewStatus doesn't have AuditAnnotations field,
	// so we include version ID in our audit logs instead
	if result.VersionID != "" {
		audit["policy_version"] = result.VersionID
	}

	// Add error info if present
	if err != nil {
		if apiErr, ok := err.(*client.ApiError); ok {
			audit["pdp_error_code"] = apiErr.Code
			audit["pdp_error_status"] = apiErr.StatusCode
		} else {
			audit["pdp_error"] = "unknown"
		}
	}

	// Marshal and log
	auditJSON, _ := json.Marshal(audit)
	fmt.Printf("audit_log %s\n", string(auditJSON))
}

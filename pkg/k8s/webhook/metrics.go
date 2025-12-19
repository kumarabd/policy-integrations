package webhook

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics holds webhook metrics.
type Metrics struct {
	// Request counters
	requestsTotal     int64 // total requests
	requestsAllow     int64 // allowed requests
	requestsDeny      int64 // denied requests
	requestsError     int64 // error requests
	
	// PDP call counters
	pdpCallsTotal     int64 // total PDP calls
	pdpCallsOK        int64 // successful PDP calls
	pdpCallsError     int64 // failed PDP calls
	
	// Cache counters
	cacheHits         int64
	cacheMisses       int64
	
	// Breaker counters
	breakerTransitions int64
	
	// Duration tracking (simple buckets)
	requestDurations  []int64 // buckets: 0-10ms, 10-50ms, 50-100ms, 100-500ms, 500ms+
	pdpDurations      []int64 // same buckets
	
	mu sync.Mutex
}

// NewMetrics creates a new metrics instance.
func NewMetrics() *Metrics {
	return &Metrics{
		requestDurations: make([]int64, 5), // 5 buckets
		pdpDurations:     make([]int64, 5),
	}
}

// IncRequestsTotal increments the total request counter.
func (m *Metrics) IncRequestsTotal() {
	atomic.AddInt64(&m.requestsTotal, 1)
}

// IncRequestsAllow increments the allowed request counter.
func (m *Metrics) IncRequestsAllow() {
	atomic.AddInt64(&m.requestsAllow, 1)
}

// IncRequestsDeny increments the denied request counter.
func (m *Metrics) IncRequestsDeny() {
	atomic.AddInt64(&m.requestsDeny, 1)
}

// IncRequestsError increments the error request counter.
func (m *Metrics) IncRequestsError() {
	atomic.AddInt64(&m.requestsError, 1)
}

// IncPDPCallsTotal increments the total PDP call counter.
func (m *Metrics) IncPDPCallsTotal() {
	atomic.AddInt64(&m.pdpCallsTotal, 1)
}

// IncPDPCallsOK increments the successful PDP call counter.
func (m *Metrics) IncPDPCallsOK() {
	atomic.AddInt64(&m.pdpCallsOK, 1)
}

// IncPDPCallsError increments the failed PDP call counter.
func (m *Metrics) IncPDPCallsError() {
	atomic.AddInt64(&m.pdpCallsError, 1)
}

// IncCacheHits increments the cache hit counter.
func (m *Metrics) IncCacheHits() {
	atomic.AddInt64(&m.cacheHits, 1)
}

// IncCacheMisses increments the cache miss counter.
func (m *Metrics) IncCacheMisses() {
	atomic.AddInt64(&m.cacheMisses, 1)
}

// IncBreakerTransitions increments the breaker transition counter.
func (m *Metrics) IncBreakerTransitions() {
	atomic.AddInt64(&m.breakerTransitions, 1)
}

// RecordRequestDuration records a request duration in the appropriate bucket.
func (m *Metrics) RecordRequestDuration(duration time.Duration) {
	ms := duration.Milliseconds()
	bucket := m.getBucket(ms)
	if bucket < len(m.requestDurations) {
		atomic.AddInt64(&m.requestDurations[bucket], 1)
	}
}

// RecordPDPDuration records a PDP call duration in the appropriate bucket.
func (m *Metrics) RecordPDPDuration(duration time.Duration) {
	ms := duration.Milliseconds()
	bucket := m.getBucket(ms)
	if bucket < len(m.pdpDurations) {
		atomic.AddInt64(&m.pdpDurations[bucket], 1)
	}
}

// getBucket returns the bucket index for a duration in milliseconds.
// Buckets: 0-10ms, 10-50ms, 50-100ms, 100-500ms, 500ms+
func (m *Metrics) getBucket(ms int64) int {
	if ms < 10 {
		return 0
	} else if ms < 50 {
		return 1
	} else if ms < 100 {
		return 2
	} else if ms < 500 {
		return 3
	}
	return 4
}

// FormatPrometheus returns metrics in Prometheus text format.
func (m *Metrics) FormatPrometheus() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	var buf []byte
	
	// Request counters
	buf = append(buf, fmt.Sprintf("# HELP pep_webhook_requests_total Total number of webhook requests\n")...)
	buf = append(buf, fmt.Sprintf("# TYPE pep_webhook_requests_total counter\n")...)
	buf = append(buf, fmt.Sprintf("pep_webhook_requests_total{result=\"allow\"} %d\n", atomic.LoadInt64(&m.requestsAllow))...)
	buf = append(buf, fmt.Sprintf("pep_webhook_requests_total{result=\"deny\"} %d\n", atomic.LoadInt64(&m.requestsDeny))...)
	buf = append(buf, fmt.Sprintf("pep_webhook_requests_total{result=\"error\"} %d\n", atomic.LoadInt64(&m.requestsError))...)
	
	// PDP call counters
	buf = append(buf, fmt.Sprintf("# HELP pep_webhook_pdp_calls_total Total number of PDP calls\n")...)
	buf = append(buf, fmt.Sprintf("# TYPE pep_webhook_pdp_calls_total counter\n")...)
	buf = append(buf, fmt.Sprintf("pep_webhook_pdp_calls_total{result=\"ok\"} %d\n", atomic.LoadInt64(&m.pdpCallsOK))...)
	buf = append(buf, fmt.Sprintf("pep_webhook_pdp_calls_total{result=\"error\"} %d\n", atomic.LoadInt64(&m.pdpCallsError))...)
	
	// Cache counters
	buf = append(buf, fmt.Sprintf("# HELP pep_webhook_cache_hits_total Total number of cache hits\n")...)
	buf = append(buf, fmt.Sprintf("# TYPE pep_webhook_cache_hits_total counter\n")...)
	buf = append(buf, fmt.Sprintf("pep_webhook_cache_hits_total %d\n", atomic.LoadInt64(&m.cacheHits))...)
	
	buf = append(buf, fmt.Sprintf("# HELP pep_webhook_cache_misses_total Total number of cache misses\n")...)
	buf = append(buf, fmt.Sprintf("# TYPE pep_webhook_cache_misses_total counter\n")...)
	buf = append(buf, fmt.Sprintf("pep_webhook_cache_misses_total %d\n", atomic.LoadInt64(&m.cacheMisses))...)
	
	// Breaker transitions
	buf = append(buf, fmt.Sprintf("# HELP pep_webhook_breaker_transitions_total Total number of circuit breaker state transitions\n")...)
	buf = append(buf, fmt.Sprintf("# TYPE pep_webhook_breaker_transitions_total counter\n")...)
	buf = append(buf, fmt.Sprintf("pep_webhook_breaker_transitions_total %d\n", atomic.LoadInt64(&m.breakerTransitions))...)
	
	// Request duration histogram
	buf = append(buf, fmt.Sprintf("# HELP pep_webhook_request_duration_ms Request duration in milliseconds\n")...)
	buf = append(buf, fmt.Sprintf("# TYPE pep_webhook_request_duration_ms histogram\n")...)
	buckets := []int64{10, 50, 100, 500, 9223372036854775807} // +Inf
	for i, bucket := range buckets {
		le := "+Inf"
		if i < len(buckets)-1 {
			le = fmt.Sprintf("%d", bucket)
		}
		count := int64(0)
		for j := 0; j <= i && j < len(m.requestDurations); j++ {
			count += atomic.LoadInt64(&m.requestDurations[j])
		}
		buf = append(buf, fmt.Sprintf("pep_webhook_request_duration_ms_bucket{le=\"%s\"} %d\n", le, count)...)
	}
	
	// PDP duration histogram
	buf = append(buf, fmt.Sprintf("# HELP pep_webhook_pdp_duration_ms PDP call duration in milliseconds\n")...)
	buf = append(buf, fmt.Sprintf("# TYPE pep_webhook_pdp_duration_ms histogram\n")...)
	for i, bucket := range buckets {
		le := "+Inf"
		if i < len(buckets)-1 {
			le = fmt.Sprintf("%d", bucket)
		}
		count := int64(0)
		for j := 0; j <= i && j < len(m.pdpDurations); j++ {
			count += atomic.LoadInt64(&m.pdpDurations[j])
		}
		buf = append(buf, fmt.Sprintf("pep_webhook_pdp_duration_ms_bucket{le=\"%s\"} %d\n", le, count)...)
	}
	
	return string(buf)
}


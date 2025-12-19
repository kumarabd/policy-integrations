package webhook

import (
	"sync"
	"sync/atomic"
	"time"
)

// BreakerState represents the state of the circuit breaker.
type BreakerState int32

const (
	// BreakerClosed means the circuit is closed and requests are allowed.
	BreakerClosed BreakerState = iota
	// BreakerOpen means the circuit is open and requests are blocked.
	BreakerOpen
	// BreakerHalfOpen means the circuit is half-open, allowing one test request.
	BreakerHalfOpen
)

// String returns the string representation of the breaker state.
func (s BreakerState) String() string {
	switch s {
	case BreakerClosed:
		return "closed"
	case BreakerOpen:
		return "open"
	case BreakerHalfOpen:
		return "half_open"
	default:
		return "unknown"
	}
}

// BreakerConfig configures the circuit breaker behavior.
type BreakerConfig struct {
	// FailureThreshold is the number of consecutive failures before opening
	FailureThreshold int
	
	// FailureWindow is the time window for counting failures
	FailureWindow time.Duration
	
	// Cooldown is the duration to wait before transitioning from OPEN to HALF_OPEN
	Cooldown time.Duration
	
	// OnStateChange is called when the breaker state changes
	OnStateChange func(from, to BreakerState)
}

// DefaultBreakerConfig returns a default circuit breaker configuration.
func DefaultBreakerConfig() BreakerConfig {
	return BreakerConfig{
		FailureThreshold: 5,
		FailureWindow:    10 * time.Second,
		Cooldown:         2 * time.Second,
	}
}

// Breaker implements a circuit breaker pattern for PDP calls.
type Breaker struct {
	config BreakerConfig
	
	// State is the current breaker state (atomic)
	state int32
	
	// Failure tracking
	mu            sync.Mutex
	failures      []time.Time
	lastOpenTime  time.Time
	halfOpenTest  bool // true if a test request is in progress
}

// NewBreaker creates a new circuit breaker.
func NewBreaker(config BreakerConfig) *Breaker {
	if config.FailureThreshold <= 0 {
		config.FailureThreshold = 5
	}
	if config.FailureWindow == 0 {
		config.FailureWindow = 10 * time.Second
	}
	if config.Cooldown == 0 {
		config.Cooldown = 2 * time.Second
	}
	
	return &Breaker{
		config:   config,
		state:    int32(BreakerClosed),
		failures: make([]time.Time, 0),
	}
}

// State returns the current breaker state.
func (b *Breaker) State() BreakerState {
	return BreakerState(atomic.LoadInt32(&b.state))
}

// Allow checks if a request is allowed through the breaker.
// Returns true if allowed, false if blocked.
func (b *Breaker) Allow() bool {
	state := b.State()
	
	switch state {
	case BreakerClosed:
		return true
	case BreakerOpen:
		// Check if cooldown has passed
		b.mu.Lock()
		cooldownPassed := time.Since(b.lastOpenTime) >= b.config.Cooldown
		b.mu.Unlock()
		
		if cooldownPassed {
			// Transition to half-open
			b.transition(BreakerOpen, BreakerHalfOpen)
			b.mu.Lock()
			b.halfOpenTest = true
			b.mu.Unlock()
			return true
		}
		return false
	case BreakerHalfOpen:
		// Only allow if no test is in progress
		b.mu.Lock()
		allowed := !b.halfOpenTest
		if allowed {
			b.halfOpenTest = true
		}
		b.mu.Unlock()
		return allowed
	default:
		return false
	}
}

// RecordSuccess records a successful request.
func (b *Breaker) RecordSuccess() {
	state := b.State()
	
	switch state {
	case BreakerClosed:
		// Clear old failures
		b.mu.Lock()
		b.cleanupFailures()
		b.mu.Unlock()
	case BreakerHalfOpen:
		// Success in half-open closes the circuit
		b.mu.Lock()
		b.halfOpenTest = false
		b.failures = b.failures[:0] // Clear failures
		b.mu.Unlock()
		b.transition(BreakerHalfOpen, BreakerClosed)
	}
}

// RecordFailure records a failed request.
func (b *Breaker) RecordFailure() {
	state := b.State()
	
	switch state {
	case BreakerClosed:
		// Add failure and check threshold
		b.mu.Lock()
		now := time.Now()
		b.failures = append(b.failures, now)
		b.cleanupFailures()
		
		if len(b.failures) >= b.config.FailureThreshold {
			b.lastOpenTime = now
			b.mu.Unlock()
			b.transition(BreakerClosed, BreakerOpen)
		} else {
			b.mu.Unlock()
		}
	case BreakerHalfOpen:
		// Failure in half-open re-opens the circuit
		b.mu.Lock()
		b.halfOpenTest = false
		b.lastOpenTime = time.Now()
		b.mu.Unlock()
		b.transition(BreakerHalfOpen, BreakerOpen)
	}
}

// transition changes the breaker state and calls the callback.
func (b *Breaker) transition(from, to BreakerState) {
	atomic.StoreInt32(&b.state, int32(to))
	if b.config.OnStateChange != nil {
		b.config.OnStateChange(from, to)
	}
}

// cleanupFailures removes failures outside the failure window.
func (b *Breaker) cleanupFailures() {
	now := time.Now()
	cutoff := now.Add(-b.config.FailureWindow)
	
	// Remove old failures
	valid := 0
	for _, t := range b.failures {
		if t.After(cutoff) {
			b.failures[valid] = t
			valid++
		}
	}
	b.failures = b.failures[:valid]
}


// Package ratelimit provides a small, dependency-free token bucket keyed by an
// arbitrary string (Phase 5.11.2).
//
// Scope is deliberate. Clearance rate-limits *credential guessing and
// privileged mutations*, not ordinary proxied traffic: an agent making many
// legitimate requests through its gateway is the normal case and must not be
// throttled into failure. So the limiters below sit on authentication
// failures, agent registration, credential rotation, and approval mutations -
// never on the proxy hot path's success case.
package ratelimit

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// Limiter is a token bucket per key: `capacity` events are allowed in a burst,
// refilling at capacity/window. Safe for concurrent use.
type Limiter struct {
	capacity int
	window   time.Duration

	mu      sync.Mutex
	buckets map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// New builds a limiter allowing `capacity` events per `window` per key.
// A non-positive capacity disables limiting entirely, which is what makes
// "unset means off" safe for local development.
func New(capacity int, window time.Duration) *Limiter {
	return &Limiter{
		capacity: capacity,
		window:   window,
		buckets:  map[string]*bucket{},
		now:      time.Now,
	}
}

// Allow consumes one token for key, reporting whether the event may proceed.
func (l *Limiter) Allow(key string) bool {
	if l == nil || l.capacity <= 0 || l.window <= 0 {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		// Bucket map is keyed by client address, so it is attacker-influenced.
		// Evict idle entries whenever we would grow it, keeping memory bounded
		// no matter how many distinct keys are cycled through.
		l.evictIdleLocked(now)
		b = &bucket{tokens: float64(l.capacity)}
		l.buckets[key] = b
	}

	// Refill for elapsed time, capped at capacity.
	if !b.lastSeen.IsZero() {
		elapsed := now.Sub(b.lastSeen)
		b.tokens += float64(l.capacity) * (float64(elapsed) / float64(l.window))
		if b.tokens > float64(l.capacity) {
			b.tokens = float64(l.capacity)
		}
	}
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// evictIdleLocked drops buckets that have had time to fully refill; they are
// indistinguishable from a fresh bucket, so forgetting them loses nothing.
func (l *Limiter) evictIdleLocked(now time.Time) {
	for key, b := range l.buckets {
		if now.Sub(b.lastSeen) > l.window {
			delete(l.buckets, key)
		}
	}
}

// ClientKey identifies the caller for limiting purposes.
//
// It uses the transport peer address only. X-Forwarded-For is deliberately
// ignored: it is client-controlled, so honouring it would let an attacker mint
// a fresh bucket per request and bypass the limit entirely. A deployment
// behind a trusted L7 proxy should terminate and re-attach identity there.
func ClientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

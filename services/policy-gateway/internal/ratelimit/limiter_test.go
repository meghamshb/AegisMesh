package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAllowsUpToCapacityThenBlocks(t *testing.T) {
	l := New(3, time.Minute)

	for i := 0; i < 3; i++ {
		if !l.Allow("client-a") {
			t.Fatalf("event %d should be allowed within capacity", i+1)
		}
	}
	if l.Allow("client-a") {
		t.Fatal("fourth event should be blocked")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l := New(1, time.Minute)

	if !l.Allow("client-a") {
		t.Fatal("first event for client-a should be allowed")
	}
	if l.Allow("client-a") {
		t.Fatal("second event for client-a should be blocked")
	}
	if !l.Allow("client-b") {
		t.Fatal("client-b must not be affected by client-a's budget")
	}
}

func TestRefillsOverTime(t *testing.T) {
	l := New(2, time.Minute)
	base := time.Now()
	l.now = func() time.Time { return base }

	if !l.Allow("c") || !l.Allow("c") {
		t.Fatal("burst up to capacity should be allowed")
	}
	if l.Allow("c") {
		t.Fatal("should be exhausted")
	}

	// Half a window restores one token.
	l.now = func() time.Time { return base.Add(30 * time.Second) }
	if !l.Allow("c") {
		t.Fatal("a token should have refilled after half a window")
	}
	if l.Allow("c") {
		t.Fatal("only one token should have refilled")
	}

	// A full window restores the whole bucket.
	l.now = func() time.Time { return base.Add(2 * time.Minute) }
	if !l.Allow("c") || !l.Allow("c") {
		t.Fatal("a full window should restore capacity")
	}
}

func TestZeroCapacityDisablesLimiting(t *testing.T) {
	l := New(0, time.Minute)
	for i := 0; i < 100; i++ {
		if !l.Allow("c") {
			t.Fatal("a non-positive capacity must disable limiting")
		}
	}
}

func TestNilLimiterAllows(t *testing.T) {
	var l *Limiter
	if !l.Allow("c") {
		t.Fatal("a nil limiter must be a no-op, not a hard block")
	}
}

// The bucket map is keyed by attacker-influenced input, so cycling keys must
// not grow it without bound.
func TestIdleBucketsAreEvicted(t *testing.T) {
	l := New(1, time.Minute)
	base := time.Now()
	l.now = func() time.Time { return base }

	for i := 0; i < 50; i++ {
		l.Allow(string(rune('a' + i%26)))
	}
	before := len(l.buckets)

	// Move well past the window and touch one new key, triggering eviction.
	l.now = func() time.Time { return base.Add(10 * time.Minute) }
	l.Allow("fresh")

	if len(l.buckets) >= before {
		t.Fatalf("idle buckets were not evicted: %d before, %d after", before, len(l.buckets))
	}
}

// X-Forwarded-For is client-controlled; honouring it would let an attacker
// mint a fresh bucket per request and bypass the limit entirely.
func TestClientKeyIgnoresForwardedForHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.7:44321"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")

	if got := ClientKey(r); got != "203.0.113.7" {
		t.Fatalf("ClientKey = %q, want the transport peer 203.0.113.7", got)
	}

	// A spoofed header must not produce a different bucket.
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.RemoteAddr = "203.0.113.7:44322"
	r2.Header.Set("X-Forwarded-For", "9.9.9.9")
	if ClientKey(r) != ClientKey(r2) {
		t.Fatal("changing X-Forwarded-For produced a different rate-limit bucket")
	}
}

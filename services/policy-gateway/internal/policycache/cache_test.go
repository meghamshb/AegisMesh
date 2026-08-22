package policycache_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/policycache"
)

// fakeFetcher is read by the cache's background refresh goroutine while the
// test goroutine mutates it, so every field needs a lock. Without one the race
// detector flags these tests and, worse, the behaviour under test becomes
// timing-dependent.
type fakeFetcher struct {
	mu       sync.Mutex
	snapshot domain.PolicySnapshot
	err      error
	calls    atomic.Int64
}

func (f *fakeFetcher) FetchSnapshot(context.Context) (domain.PolicySnapshot, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return domain.PolicySnapshot{}, f.err
	}
	return f.snapshot, nil
}

// setSnapshot and setErr are how a test changes what the control plane would
// return mid-run.
func (f *fakeFetcher) setSnapshot(s domain.PolicySnapshot) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snapshot = s
	f.err = nil
}

func (f *fakeFetcher) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestStartFailsClosedWhenInitialFetchFails(t *testing.T) {
	fetcher := &fakeFetcher{err: errors.New("control plane unreachable")}
	cache := policycache.New(fetcher, time.Minute, testLogger())

	err := cache.Start(context.Background(), time.Hour)
	if err == nil {
		t.Fatal("expected Start to fail closed when the initial fetch errors")
	}

	if _, ok := cache.Rules(); ok {
		t.Fatal("Rules() should not be ok before any successful load")
	}
}

func TestStartLoadsInitialSnapshot(t *testing.T) {
	fetcher := &fakeFetcher{snapshot: domain.PolicySnapshot{
		OrgID:   "org-1",
		Version: 5,
		Rules:   []domain.PolicyRule{{ID: "rule-1"}},
	}}
	cache := policycache.New(fetcher, time.Minute, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := cache.Start(ctx, time.Hour); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	rules, ok := cache.Rules()
	if !ok {
		t.Fatal("expected Rules() to be ok after successful initial load")
	}
	if len(rules) != 1 || rules[0].ID != "rule-1" {
		t.Fatalf("unexpected rules: %+v", rules)
	}

	health := cache.Health()
	if health["version"] != int64(5) {
		t.Fatalf("health version = %v, want 5", health["version"])
	}
	if health["stale"] != false {
		t.Fatalf("health stale = %v, want false", health["stale"])
	}
}

func TestRefreshUpdatesSnapshot(t *testing.T) {
	fetcher := &fakeFetcher{snapshot: domain.PolicySnapshot{Version: 1, Rules: []domain.PolicyRule{{ID: "v1"}}}}
	cache := policycache.New(fetcher, time.Minute, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := cache.Start(ctx, 10*time.Millisecond); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	fetcher.setSnapshot(domain.PolicySnapshot{Version: 2, Rules: []domain.PolicyRule{{ID: "v2"}}})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rules, ok := cache.Rules()
		if ok && len(rules) == 1 && rules[0].ID == "v2" {
			return // success
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("cache did not pick up the refreshed snapshot in time")
}

func TestRulesFailsClosedWhenStale(t *testing.T) {
	fetcher := &fakeFetcher{snapshot: domain.PolicySnapshot{Version: 1, Rules: []domain.PolicyRule{{ID: "r1"}}}}
	cache := policycache.New(fetcher, 20*time.Millisecond, testLogger())

	if err := cache.Start(context.Background(), time.Hour); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if _, ok := cache.Rules(); !ok {
		t.Fatal("expected Rules() ok immediately after load")
	}

	time.Sleep(50 * time.Millisecond)

	if _, ok := cache.Rules(); ok {
		t.Fatal("expected Rules() to fail closed once the snapshot exceeds maxStale")
	}

	health := cache.Health()
	if health["stale"] != true {
		t.Fatalf("health stale = %v, want true", health["stale"])
	}
}

func TestRefreshFailureKeepsLastKnownGood(t *testing.T) {
	fetcher := &fakeFetcher{snapshot: domain.PolicySnapshot{Version: 1, Rules: []domain.PolicyRule{{ID: "good"}}}}
	cache := policycache.New(fetcher, time.Minute, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := cache.Start(ctx, 10*time.Millisecond); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Control plane becomes unreachable; refresh attempts will fail from here on.
	fetcher.setErr(errors.New("temporarily unreachable"))
	time.Sleep(50 * time.Millisecond)

	rules, ok := cache.Rules()
	if !ok {
		t.Fatal("expected last-known-good rules to still be served while within maxStale")
	}
	if len(rules) != 1 || rules[0].ID != "good" {
		t.Fatalf("unexpected rules after failed refresh: %+v", rules)
	}
}

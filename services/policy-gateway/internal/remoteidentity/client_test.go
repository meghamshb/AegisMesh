package remoteidentity_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/identity"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/remoteidentity"
)

func TestClientAuthenticateSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer clr_gateway_test" {
			t.Errorf("missing/incorrect gateway Authorization header: %q", r.Header.Get("Authorization"))
		}
		var body struct {
			TokenHash string `json:"token_hash"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.TokenHash != "abc123" {
			t.Errorf("token_hash = %q, want abc123", body.TokenHash)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"agent_id": "agent-1", "user_id": "user-1", "org_id": "org-1",
			"agent_status": "active", "user_status": "active", "org_status": "active",
		})
	}))
	defer srv.Close()

	client := remoteidentity.NewClient(srv.URL, "clr_gateway_test")
	id, err := client.Authenticate(context.Background(), "abc123")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if id.AgentID != "agent-1" || id.UserID != "user-1" || id.OrgID != "org-1" {
		t.Fatalf("unexpected identity: %+v", id)
	}
}

func TestClientAuthenticateInvalidToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := remoteidentity.NewClient(srv.URL, "clr_gateway_test")
	_, err := client.Authenticate(context.Background(), "bad-hash")
	if !errors.Is(err, identity.ErrInvalidToken) {
		t.Fatalf("error = %v, want ErrInvalidToken", err)
	}
}

func TestClientAuthenticateAgentRevoked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	client := remoteidentity.NewClient(srv.URL, "clr_gateway_test")
	_, err := client.Authenticate(context.Background(), "some-hash")
	if !errors.Is(err, identity.ErrAgentRevoked) {
		t.Fatalf("error = %v, want ErrAgentRevoked", err)
	}
}

func TestCachedClientCachesPositiveResults(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		json.NewEncoder(w).Encode(map[string]any{
			"agent_id": "agent-1", "user_id": "user-1", "org_id": "org-1",
			"agent_status": "active", "user_status": "active", "org_status": "active",
		})
	}))
	defer srv.Close()

	cached := remoteidentity.NewCachedClient(remoteidentity.NewClient(srv.URL, "tok"), time.Minute)

	for i := 0; i < 5; i++ {
		if _, err := cached.Authenticate(context.Background(), "abc123"); err != nil {
			t.Fatalf("Authenticate() error = %v", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("expected exactly 1 upstream call for 5 requests within TTL, got %d", calls.Load())
	}
}

func TestCachedClientDoesNotCacheErrors(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	cached := remoteidentity.NewCachedClient(remoteidentity.NewClient(srv.URL, "tok"), time.Minute)

	for i := 0; i < 3; i++ {
		if _, err := cached.Authenticate(context.Background(), "bad-hash"); !errors.Is(err, identity.ErrInvalidToken) {
			t.Fatalf("error = %v, want ErrInvalidToken", err)
		}
	}
	if calls.Load() != 3 {
		t.Fatalf("expected every failed lookup to hit upstream (no negative caching), got %d calls", calls.Load())
	}
}

func TestCachedClientExpiresAfterTTL(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		json.NewEncoder(w).Encode(map[string]any{
			"agent_id": "agent-1", "user_id": "user-1", "org_id": "org-1",
			"agent_status": "active", "user_status": "active", "org_status": "active",
		})
	}))
	defer srv.Close()

	cached := remoteidentity.NewCachedClient(remoteidentity.NewClient(srv.URL, "tok"), 20*time.Millisecond)

	if _, err := cached.Authenticate(context.Background(), "abc123"); err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	time.Sleep(40 * time.Millisecond)
	if _, err := cached.Authenticate(context.Background(), "abc123"); err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("expected a second upstream call after TTL expiry, got %d calls", calls.Load())
	}
}

// Only successful authentications are cached, so the key space is bounded by
// valid credentials - but each rotation mints a new hash, and an entry that is
// never evicted is a slow leak in a long-running gateway.
func TestCacheEvictsExpiredEntries(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"agent_id":"a","user_id":"u","org_id":"o"}`))
	}))
	defer srv.Close()

	// A TTL that has already elapsed by the time the next call happens.
	cached := remoteidentity.NewCachedClient(
		remoteidentity.NewClient(srv.URL, "clr_gateway_test"), time.Nanosecond)

	for i := 0; i < 50; i++ {
		if _, err := cached.Authenticate(context.Background(), fmt.Sprintf("hash-%d", i)); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
	}

	if got := cached.CacheSize(); got > 2 {
		t.Fatalf("cache holds %d entries after 50 rotations; expired entries are not evicted", got)
	}
}

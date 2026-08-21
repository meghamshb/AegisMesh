package fleet_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/fleet"
)

const testToken = "clr_gateway_test-token"

type stubPolicy struct{ version int64 }

func (s stubPolicy) Health() map[string]any {
	return map[string]any{"version": s.version, "loaded": true}
}

type stubAgents struct {
	mu     sync.Mutex
	counts []int
	next   int
}

func (s *stubAgents) DrainRecentAgentCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts = append(s.counts, s.next)
	return s.next
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// recordedBeat is one heartbeat the fake control plane received.
type recordedBeat struct {
	path          string
	authorization string
	Version       string `json:"version"`
	PolicyVersion int64  `json:"policy_version"`
	ActiveAgents  int    `json:"active_agents"`
}

type fakeControlPlane struct {
	mu       sync.Mutex
	beats    []recordedBeat
	selfCode int
	beatCode int
	gwID     string
}

func newFakeControlPlane() *fakeControlPlane {
	return &fakeControlPlane{selfCode: http.StatusOK, beatCode: http.StatusOK, gwID: "gw-1"}
}

func (f *fakeControlPlane) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/api/internal/v1/gateways/self", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		code, id := f.selfCode, f.gwID
		f.mu.Unlock()
		if code != http.StatusOK {
			w.WriteHeader(code)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "name": "gateway-a"})
	})

	mux.HandleFunc("/api/internal/v1/gateways/", func(w http.ResponseWriter, r *http.Request) {
		var beat recordedBeat
		_ = json.NewDecoder(r.Body).Decode(&beat)
		beat.path = r.URL.Path
		beat.authorization = r.Header.Get("Authorization")

		f.mu.Lock()
		f.beats = append(f.beats, beat)
		code := f.beatCode
		f.mu.Unlock()

		w.WriteHeader(code)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func (f *fakeControlPlane) recorded() []recordedBeat {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedBeat(nil), f.beats...)
}

func TestIdentifyResolvesGatewayIDFromCredential(t *testing.T) {
	cp := newFakeControlPlane()
	srv := cp.server(t)

	r := fleet.NewReporter(srv.URL, testToken, "test-build", stubPolicy{}, &stubAgents{}, discardLogger())
	if err := r.Identify(context.Background()); err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if r.GatewayID() != "gw-1" {
		t.Fatalf("GatewayID = %q, want gw-1", r.GatewayID())
	}
	if r.Name() != "gateway-a" {
		t.Fatalf("Name = %q, want gateway-a", r.Name())
	}
}

func TestIdentifyFailsOnRejectedCredential(t *testing.T) {
	cp := newFakeControlPlane()
	cp.selfCode = http.StatusUnauthorized
	srv := cp.server(t)

	r := fleet.NewReporter(srv.URL, testToken, "test-build", stubPolicy{}, &stubAgents{}, discardLogger())
	if err := r.Identify(context.Background()); err == nil {
		t.Fatal("expected an error when the control plane rejects the credential")
	}
}

func TestHeartbeatReportsPolicyVersionAndAgents(t *testing.T) {
	cp := newFakeControlPlane()
	srv := cp.server(t)

	agents := &stubAgents{next: 3}
	r := fleet.NewReporter(srv.URL, testToken, "v9.9.9", stubPolicy{version: 42}, agents, discardLogger())
	if err := r.Identify(context.Background()); err != nil {
		t.Fatalf("Identify: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx, time.Hour) // long interval: only the immediate beat should fire

	beats := waitForBeats(t, cp, 1)
	got := beats[0]

	if got.path != "/api/internal/v1/gateways/gw-1/heartbeat" {
		t.Fatalf("heartbeat path = %q", got.path)
	}
	if got.authorization != "Bearer "+testToken {
		t.Fatalf("heartbeat did not present the gateway credential: %q", got.authorization)
	}
	if got.Version != "v9.9.9" {
		t.Fatalf("version = %q, want v9.9.9", got.Version)
	}
	if got.PolicyVersion != 42 {
		t.Fatalf("policy_version = %d, want 42", got.PolicyVersion)
	}
	if got.ActiveAgents != 3 {
		t.Fatalf("active_agents = %d, want 3", got.ActiveAgents)
	}
}

// A gateway that boots while the control plane is down must still join the
// fleet view once it recovers, without being restarted.
func TestHeartbeatRecoversIdentityAfterControlPlaneOutage(t *testing.T) {
	cp := newFakeControlPlane()
	cp.selfCode = http.StatusServiceUnavailable
	srv := cp.server(t)

	r := fleet.NewReporter(srv.URL, testToken, "test-build", stubPolicy{version: 7}, &stubAgents{}, discardLogger())
	if err := r.Identify(context.Background()); err == nil {
		t.Fatal("expected Identify to fail while the control plane is down")
	}
	if r.GatewayID() != "" {
		t.Fatalf("GatewayID should be empty after a failed Identify, got %q", r.GatewayID())
	}

	// Control plane comes back.
	cp.mu.Lock()
	cp.selfCode = http.StatusOK
	cp.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx, 50*time.Millisecond)

	beats := waitForBeats(t, cp, 1)
	if beats[0].PolicyVersion != 7 {
		t.Fatalf("policy_version = %d, want 7", beats[0].PolicyVersion)
	}
	if r.GatewayID() != "gw-1" {
		t.Fatalf("reporter did not recover its identity, GatewayID = %q", r.GatewayID())
	}
}

// Heartbeats are reporting, not enforcement: a rejected beat must not stop the
// loop, because the gateway is still enforcing policy correctly meanwhile.
func TestHeartbeatFailuresDoNotStopTheLoop(t *testing.T) {
	cp := newFakeControlPlane()
	cp.beatCode = http.StatusInternalServerError
	srv := cp.server(t)

	r := fleet.NewReporter(srv.URL, testToken, "test-build", stubPolicy{}, &stubAgents{}, discardLogger())
	if err := r.Identify(context.Background()); err != nil {
		t.Fatalf("Identify: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx, 30*time.Millisecond)

	// Two beats means the loop survived the first failure.
	waitForBeats(t, cp, 2)
}

func waitForBeats(t *testing.T, cp *fakeControlPlane, want int) []recordedBeat {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if beats := cp.recorded(); len(beats) >= want {
			return beats
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d heartbeat(s), got %d", want, len(cp.recorded()))
	return nil
}

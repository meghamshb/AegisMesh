package app_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/app"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/config"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store/storetest"
)

// noopStore exists only to prove HTTP-surface separation between
// ControlHandler and ProxyHandler; no test here exercises real business
// logic (that's covered in internal/api, internal/proxy, internal/service),
// so the zero-value stub is all it needs.
type noopStore struct{ storetest.Stub }

func testApp() *app.App {
	cfg := config.Config{
		ServiceName:    "policy-gateway",
		ServiceVersion: "test",
		ProxyEnabled:   true,
		AgentAuthMode:  config.AgentAuthModeStatic,
	}
	return app.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), noopStore{})
}

func TestControlHandlerServesHealthNotProxy(t *testing.T) {
	a := testApp()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	a.ControlHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /health via ControlHandler: status = %d, want 200", rec.Code)
	}
}

func TestControlHandlerDoesNotForwardCONNECT(t *testing.T) {
	a := testApp()

	// A CONNECT request looks like proxy traffic, but ControlHandler must
	// never dispatch to the data-plane forwarder: no route in the
	// control-plane mux matches CONNECT, so it 404s instead of tunneling.
	req := httptest.NewRequest(http.MethodConnect, "/", nil)
	req.Host = "example.com:443"
	rec := httptest.NewRecorder()
	a.ControlHandler().ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("ControlHandler must not tunnel CONNECT requests, got status %d", rec.Code)
	}
}

func TestProxyHandlerDoesNotServeControlPlaneRoutes(t *testing.T) {
	a := testApp()

	// /api/v1/users is a control-plane route; ProxyHandler only knows how to
	// evaluate egress traffic, so this must not return a user list.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	rec := httptest.NewRecorder()
	a.ProxyHandler().ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("ProxyHandler must not serve control-plane routes, got status %d, body=%s", rec.Code, rec.Body.String())
	}
}

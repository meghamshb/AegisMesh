package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Redirect handling is a security property, not a convenience one: if the
// gateway followed redirects itself, an approved public host could redirect to
// 169.254.169.254 and the gateway would fetch it, having already passed the
// SSRF check against the *original* host. Every hop must be a fresh decision.
//
// This is asserted here rather than in the live evaluation harness because
// producing a real public-to-private redirect requires an external redirector,
// and a security claim should not depend on a third party's uptime or
// behaviour. The harness records these IDs as covered by this test.

// EGR-11: the gateway's transport must not follow redirects. The 302 is
// handed back to the client, whose next request is proxied and evaluated on
// its own merits.
func TestForwardHTTPDoesNotFollowRedirects(t *testing.T) {
	var privateHitCount int

	// Stands in for the internal target a redirect would try to reach.
	private := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		privateHitCount++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("INTERNAL SECRET"))
	}))
	defer private.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, private.URL+"/latest/meta-data/", http.StatusFound)
	}))
	defer redirector.Close()

	h := &Handler{
		transport: &http.Transport{},
		logger:    testLogger(),
	}

	req := httptest.NewRequest(http.MethodGet, redirector.URL+"/start", nil)
	rec := httptest.NewRecorder()
	h.forwardHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 passed through to the client", rec.Code)
	}
	if privateHitCount != 0 {
		t.Fatalf("gateway followed the redirect and fetched the internal target %d time(s); "+
			"each hop must be re-evaluated as a new proxied request", privateHitCount)
	}
	if body := rec.Body.String(); body == "INTERNAL SECRET" {
		t.Fatal("internal content reached the client through a followed redirect")
	}

	// The Location header is returned so the client can decide - and its next
	// request will go through the proxy and hit the SSRF guard.
	if loc := rec.Header().Get("Location"); loc == "" {
		t.Fatal("Location header was not passed back to the client")
	}
}

// EGR-12: the location a redirect points at gets the same treatment as any
// other destination - the guard does not care that it arrived via a redirect.
func TestRedirectTargetIsSubjectToTheSSRFGuard(t *testing.T) {
	guard := NewUpstreamGuard()

	// Whatever a permitted host redirects to, these targets stay blocked when
	// the client re-requests them through the proxy.
	for _, target := range []string{"169.254.169.254", "127.0.0.1", "10.0.0.1", "::1"} {
		if blocked, _ := guard.IsBlocked(target); !blocked {
			t.Fatalf("redirect target %q would be permitted on the second hop", target)
		}
	}
}

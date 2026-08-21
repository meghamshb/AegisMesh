package api_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/api"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/config"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/identity"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/policy"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/service"
)

// Phase 5.11 security hardening.

const testAdminToken = "correct-admin-token"

// securityServer builds a server with real auth and tight rate limits, so the
// limiter is actually exercised rather than sitting at its permissive default.
func securityServer(t *testing.T, st stubStore, authLimit, mutationLimit int) *api.Server {
	t.Helper()
	cfg := config.Config{
		ServiceName:      "policy-gateway",
		ServiceVersion:   "test",
		AdminToken:       testAdminToken,
		Identity:         config.AgentIdentity{OrgID: "org-1", UserID: "user-1", AgentID: "agent-1"},
		AuthFailureLimit: authLimit,
		MutationLimit:    mutationLimit,
		RateLimitWindow:  time.Minute,
	}
	egress := service.NewEgress(st, policy.NewRuleEngine(st))
	return api.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), st, egress, identity.NewService(st))
}

func send(srv *api.Server, method, path string, headers map[string]string, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	// httptest gives every request the same RemoteAddr, which is what we want:
	// one client hammering the endpoint.
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// 5.11.2 — credential guessing must not be free.
func TestAdminAuthFailuresAreRateLimited(t *testing.T) {
	srv := securityServer(t, testDirectoryFixtures(), 3, 100)
	bad := map[string]string{"X-Admin-Token": "wrong"}

	for i := 0; i < 3; i++ {
		if code := send(srv, http.MethodGet, "/api/v1/users", bad, "").Code; code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i+1, code)
		}
	}

	rec := send(srv, http.MethodGet, "/api/v1/users", bad, "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 once the failure budget is spent", rec.Code)
	}
}

func TestGatewayAuthFailuresAreRateLimited(t *testing.T) {
	fixtures, _ := gatewayFixture(t)
	srv := securityServer(t, fixtures, 3, 100)
	bad := map[string]string{"Authorization": "Bearer clr_gateway_wrong"}

	for i := 0; i < 3; i++ {
		if code := send(srv, http.MethodGet, "/api/internal/v1/policies/snapshot", bad, "").Code; code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i+1, code)
		}
	}

	rec := send(srv, http.MethodGet, "/api/internal/v1/policies/snapshot", bad, "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 once the failure budget is spent", rec.Code)
	}
}

// Credential-minting operations are limited even for an authenticated admin,
// so a stolen admin token cannot be used to bulk-mint agent credentials.
func TestPrivilegedMutationsAreRateLimited(t *testing.T) {
	srv := securityServer(t, testDirectoryFixtures(), 100, 2)
	good := map[string]string{"X-Admin-Token": testAdminToken, "Content-Type": "application/json"}

	for i := 0; i < 2; i++ {
		rec := send(srv, http.MethodPost, "/api/v1/agents/agent-1/credentials/rotate", good, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("attempt %d: status = %d, want 200 (body=%s)", i+1, rec.Code, rec.Body.String())
		}
	}

	rec := send(srv, http.MethodPost, "/api/v1/agents/agent-1/credentials/rotate", good, "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 once the mutation budget is spent", rec.Code)
	}
}

// The limiter must not be so broad it breaks ordinary console use: an operator
// refreshing the inbox must never be throttled out of seeing pending requests.
func TestReadsAreNotRateLimited(t *testing.T) {
	srv := securityServer(t, testDirectoryFixtures(), 2, 2)
	good := map[string]string{"X-Admin-Token": testAdminToken}

	for i := 0; i < 50; i++ {
		if code := send(srv, http.MethodGet, "/api/v1/requests", good, "").Code; code != http.StatusOK {
			t.Fatalf("read %d: status = %d, want 200 - reads must not be rate limited", i+1, code)
		}
	}
}

// A successful auth must not consume failure budget, or a busy legitimate
// operator would lock themselves out.
func TestSuccessfulAuthDoesNotConsumeFailureBudget(t *testing.T) {
	srv := securityServer(t, testDirectoryFixtures(), 2, 100)
	good := map[string]string{"X-Admin-Token": testAdminToken}

	for i := 0; i < 20; i++ {
		send(srv, http.MethodGet, "/api/v1/users", good, "")
	}

	// The failure budget should still be intact.
	bad := map[string]string{"X-Admin-Token": "wrong"}
	if code := send(srv, http.MethodGet, "/api/v1/users", bad, "").Code; code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 - successful auths should not have spent the failure budget", code)
	}
}

// ---------------------------------------------------------------------------
// 5.11.6 — the rule the spec calls out as important:
// "Org A agent token cannot be accepted by gateway registered to Org B."
// Even though the token resolves globally, the gateway's org must equal the
// agent's org, and a mismatch must be rejected.
// ---------------------------------------------------------------------------

func TestGatewayCannotAuthenticateAgentFromAnotherOrg(t *testing.T) {
	orgBGatewayToken := "clr_gateway_org-b-token"
	orgAAgentToken := "clr_agent_org-a-token"

	st := testDirectoryFixtures()
	// A gateway that belongs to org-2.
	st.gateways = []domain.Gateway{
		{ID: "gw-org-b", OrgID: "org-2", Name: "org-b-gateway", Status: "active",
			CredentialHash: identity.HashToken(orgBGatewayToken)},
	}
	// An agent, and its credential, that belong to org-1.
	st.agents = []domain.Agent{
		{ID: "agent-org-a", OrgID: "org-1", OwnerUserID: "user-1", Name: "org-a-agent", Status: "active"},
	}
	st.credentials = []domain.AgentCredential{
		{ID: "cred-1", AgentID: "agent-org-a", Status: "active",
			TokenHash: identity.HashAgentToken(orgAAgentToken)},
	}
	st.organization = domain.Organization{ID: "org-1", Slug: "default", Name: "Default", Status: "active"}

	srv := securityServer(t, st, 100, 100)

	rec := send(srv, http.MethodPost, "/api/internal/v1/agents/authenticate",
		map[string]string{
			"Authorization": "Bearer " + orgBGatewayToken,
			"Content-Type":  "application/json",
		},
		`{"token_hash":"`+identity.HashAgentToken(orgAAgentToken)+`"}`)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: an org-B gateway must not resolve an org-A agent (body=%s)",
			rec.Code, rec.Body.String())
	}
	// The rejection must not leak that the agent exists elsewhere.
	if strings.Contains(rec.Body.String(), "agent-org-a") || strings.Contains(rec.Body.String(), "org-1") {
		t.Fatalf("cross-org rejection leaked the agent's real identity: %s", rec.Body.String())
	}
}

// The same gateway must still resolve an agent that really is in its own org,
// so the test above proves org matching rather than blanket failure.
func TestGatewayResolvesAgentFromItsOwnOrg(t *testing.T) {
	gatewayToken := "clr_gateway_org-a-token"
	agentToken := "clr_agent_same-org-token"

	st := testDirectoryFixtures()
	st.gateways = []domain.Gateway{
		{ID: "gw-org-a", OrgID: "org-1", Name: "org-a-gateway", Status: "active",
			CredentialHash: identity.HashToken(gatewayToken)},
	}
	st.agents = []domain.Agent{
		{ID: "agent-1", OrgID: "org-1", OwnerUserID: "user-1", Name: "org-a-agent", Status: "active"},
	}
	st.credentials = []domain.AgentCredential{
		{ID: "cred-1", AgentID: "agent-1", Status: "active", TokenHash: identity.HashAgentToken(agentToken)},
	}
	st.organization = domain.Organization{ID: "org-1", Slug: "default", Name: "Default", Status: "active"}

	srv := securityServer(t, st, 100, 100)

	rec := send(srv, http.MethodPost, "/api/internal/v1/agents/authenticate",
		map[string]string{
			"Authorization": "Bearer " + gatewayToken,
			"Content-Type":  "application/json",
		},
		`{"token_hash":"`+identity.HashAgentToken(agentToken)+`"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an agent in the gateway's own org (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "agent-1") {
		t.Fatalf("expected the resolved agent id in the response: %s", rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 5.11.8 — private network is not authentication.
// ---------------------------------------------------------------------------

func TestInternalEndpointsRequireGatewayCredential(t *testing.T) {
	fixtures, _ := gatewayFixture(t)
	srv := securityServer(t, fixtures, 100, 100)

	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/internal/v1/gateways/self", ""},
		{http.MethodGet, "/api/internal/v1/policies/snapshot", ""},
		{http.MethodPost, "/api/internal/v1/gateways/gw-1/heartbeat", `{}`},
		{http.MethodPost, "/api/internal/v1/agents/authenticate", `{"token_hash":"abc"}`},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			// No credential at all - as if arriving from "inside" the network.
			rec := send(srv, tc.method, tc.path, nil, tc.body)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401: a private network is not authentication", rec.Code)
			}

			// An admin token must not substitute for a gateway credential
			// either - these are separate trust domains.
			rec = send(srv, tc.method, tc.path,
				map[string]string{"X-Admin-Token": testAdminToken}, tc.body)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401: the admin token is not a gateway credential", rec.Code)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 5.11 acceptance: no plaintext credential ever leaves the API.
// ---------------------------------------------------------------------------

func TestCredentialHashIsNeverSerialized(t *testing.T) {
	fixtures, token := gatewayFixture(t)
	srv := securityServer(t, fixtures, 100, 100)
	good := map[string]string{"X-Admin-Token": testAdminToken}

	for _, path := range []string{"/api/v1/gateways", "/api/v1/gateways/gw-1"} {
		rec := send(srv, http.MethodGet, path, good, "")
		body := rec.Body.String()
		if strings.Contains(body, "credential_hash") {
			t.Fatalf("%s serialized credential_hash: %s", path, body)
		}
		if strings.Contains(body, identity.HashToken(token)) {
			t.Fatalf("%s leaked the raw credential hash value", path)
		}
		if strings.Contains(body, token) {
			t.Fatalf("%s leaked the plaintext gateway token", path)
		}
	}
}

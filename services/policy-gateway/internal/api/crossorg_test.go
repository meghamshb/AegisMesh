package api_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/api"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/config"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/identity"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/policy"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/service"
)

// These tests all run as an authenticated admin of org-1 against a store that
// also holds org-2 data, and assert that org-2's rows are neither readable nor
// mutable. Every id used below is a *real* row in the store - the handler must
// reject it on tenancy grounds, not because the id is unknown.
//
// The expected status is 404, never 403: a 403 would confirm the row exists
// and turn these endpoints into a cross-tenant existence oracle.

const otherOrg = "org-2"

func twoOrgFixtures() stubStore {
	return stubStore{
		organization: domain.Organization{ID: "org-1", Slug: "default", Name: "Default Organization", Status: "active"},
		users: []domain.User{
			{ID: "user-1", OrgID: "org-1", DisplayName: "Alice", Role: "member", Status: "active"},
			{ID: "victim-user", OrgID: otherOrg, DisplayName: "Mallory", Role: "admin", Status: "active"},
		},
		agents: []domain.Agent{
			{ID: "agent-1", OrgID: "org-1", OwnerUserID: "user-1", Name: "alice-hermes", Status: "active"},
			{ID: "victim-agent", OrgID: otherOrg, OwnerUserID: "victim-user", Name: "victim-hermes", Status: "active"},
		},
		gateways: []domain.Gateway{
			{ID: "gw-1", OrgID: "org-1", Name: "ours", Status: "active"},
			{ID: "victim-gw", OrgID: otherOrg, Name: "theirs", Status: "active"},
		},
		rules: []domain.PolicyRule{
			{ID: "rule-1", OrgID: "org-1", Scope: domain.RuleScopeOrg, Effect: domain.RuleEffectAllow, Host: "ours.example.com"},
			{ID: "victim-rule", OrgID: otherOrg, Scope: domain.RuleScopeOrg, Effect: domain.RuleEffectAllow, Host: "secret.example.com"},
		},
		requests: []domain.EgressRequest{
			{ID: "req-1", OrgID: "org-1", Status: domain.RequestStatusPending, Host: "ours.example.com", Method: "GET", Path: "/"},
			{ID: "victim-req", OrgID: otherOrg, Status: domain.RequestStatusPending, Host: "secret.example.com", Method: "GET", Path: "/"},
		},
		auditEvents: []domain.AuditEvent{
			{ID: "audit-1", OrgID: "org-1", EventType: "egress_auto_approved"},
			{ID: "victim-audit", OrgID: otherOrg, EventType: "egress_denied"},
		},
	}
}

func crossOrgServer(t *testing.T) *api.Server {
	t.Helper()
	st := twoOrgFixtures()
	cfg := config.Config{
		ServiceName:    "policy-gateway",
		ServiceVersion: "test",
		Identity:       config.AgentIdentity{OrgID: "org-1", UserID: "user-1", AgentID: "agent-1"},
	}
	egress := service.NewEgress(st, policy.NewRuleEngine(st))
	return api.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), st, egress, identity.NewService(st))
}

func do(t *testing.T, srv *api.Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// itemIDs pulls the "items" array ids out of a paginated list response.
func itemIDs(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()
	var payload struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal list response: %v (body=%s)", err, rec.Body.String())
	}
	ids := make([]string, 0, len(payload.Items))
	for _, item := range payload.Items {
		ids = append(ids, item.ID)
	}
	return ids
}

func assertNoForeignIDs(t *testing.T, ids []string, forbidden ...string) {
	t.Helper()
	for _, id := range ids {
		for _, bad := range forbidden {
			if id == bad {
				t.Fatalf("list leaked another organization's row %q (got %v)", bad, ids)
			}
		}
	}
}

func TestListEndpointsDoNotLeakOtherOrgs(t *testing.T) {
	srv := crossOrgServer(t)

	for _, tc := range []struct {
		name      string
		path      string
		forbidden string
		expected  string
	}{
		{"users", "/api/v1/users", "victim-user", "user-1"},
		{"agents", "/api/v1/agents", "victim-agent", "agent-1"},
		{"rules", "/api/v1/rules", "victim-rule", "rule-1"},
		{"requests", "/api/v1/requests", "victim-req", "req-1"},
		{"audit", "/api/v1/audit", "victim-audit", "audit-1"},
		{"gateways", "/api/v1/gateways", "victim-gw", "gw-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, srv, http.MethodGet, tc.path, "")
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s: status = %d, want 200 (body=%s)", tc.path, rec.Code, rec.Body.String())
			}
			ids := itemIDs(t, rec)
			assertNoForeignIDs(t, ids, tc.forbidden)
			// Guard against the test passing because the list is simply empty.
			var found bool
			for _, id := range ids {
				if id == tc.expected {
					found = true
				}
			}
			if !found {
				t.Fatalf("GET %s: own-org row %q missing, list was %v", tc.path, tc.expected, ids)
			}
		})
	}
}

func TestReadByIDRejectsOtherOrg(t *testing.T) {
	srv := crossOrgServer(t)

	for _, tc := range []struct{ name, path string }{
		{"user", "/api/v1/users/victim-user"},
		{"agent", "/api/v1/agents/victim-agent"},
		{"gateway", "/api/v1/gateways/victim-gw"},
		{"request", "/api/v1/requests/victim-req"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, srv, http.MethodGet, tc.path, "")
			if rec.Code != http.StatusNotFound {
				t.Fatalf("GET %s: status = %d, want 404 (body=%s)", tc.path, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestMutationsRejectOtherOrg(t *testing.T) {
	srv := crossOrgServer(t)

	for _, tc := range []struct {
		name, method, path, body string
	}{
		{"update user", http.MethodPatch, "/api/v1/users/victim-user", `{"role":"member"}`},
		{"update agent", http.MethodPatch, "/api/v1/agents/victim-agent", `{"name":"pwned"}`},
		{"revoke agent", http.MethodPost, "/api/v1/agents/victim-agent/revoke", ""},
		{"revoke rule", http.MethodDelete, "/api/v1/rules/victim-rule", ""},
		{"approve request", http.MethodPost, "/api/v1/requests/victim-req/approve", `{}`},
		{"deny request", http.MethodPost, "/api/v1/requests/victim-req/deny", `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, srv, tc.method, tc.path, tc.body)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("%s %s: status = %d, want 404 (body=%s)", tc.method, tc.path, rec.Code, rec.Body.String())
			}
		})
	}
}

// The highest-severity case from the audit: credential rotation hands back a
// live agent token. If it were not org-scoped, knowing another tenant's agent
// UUID would be enough to be issued a working credential for that agent.
func TestRotateCredentialRejectsOtherOrgAgent(t *testing.T) {
	srv := crossOrgServer(t)

	rec := do(t, srv, http.MethodPost, "/api/v1/agents/victim-agent/credentials/rotate", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("rotate other org's agent: status = %d, want 404 (body=%s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "clr_agent_") {
		t.Fatalf("rotate other org's agent leaked a credential: %s", rec.Body.String())
	}
}

// Rotation must still work for an agent we do own, so the test above is
// proving tenancy enforcement rather than a blanket failure.
func TestRotateCredentialSucceedsForOwnAgent(t *testing.T) {
	srv := crossOrgServer(t)

	rec := do(t, srv, http.MethodPost, "/api/v1/agents/agent-1/credentials/rotate", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate own agent: status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "clr_agent_") {
		t.Fatalf("rotate own agent did not return a token: %s", rec.Body.String())
	}
}

// Registering an agent must not be able to attach it to another org's user,
// even though that user id is real.
func TestRegisterAgentRejectsOtherOrgOwner(t *testing.T) {
	srv := crossOrgServer(t)

	rec := do(t, srv, http.MethodPost, "/api/v1/agents", `{"owner_user_id":"victim-user","name":"sneaky"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("register agent with other org's owner: status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}

// A rule may not be scoped to a subject that lives in another organization.
func TestCreateRuleRejectsOtherOrgScopeRef(t *testing.T) {
	srv := crossOrgServer(t)

	for _, tc := range []struct{ name, body string }{
		{"user scope", `{"scope":"user","scope_ref_id":"victim-user","effect":"allow","host":"x.example.com"}`},
		{"agent scope", `{"scope":"agent","scope_ref_id":"victim-agent","effect":"allow","host":"x.example.com"}`},
		{"org scope", `{"scope":"org","scope_ref_id":"org-2","effect":"allow","host":"x.example.com"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, srv, http.MethodPost, "/api/v1/rules", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("create rule scoped to other org: status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
			}
		})
	}
}

// A gateway credential is bound to one org. It must not be usable to fetch a
// different tenant's policy snapshot, nor to resolve an agent outside its org.
func TestGatewaySnapshotIsScopedToCredentialOrg(t *testing.T) {
	token := "clr_gateway_org2-token"
	st := twoOrgFixtures()
	st.gateways = append(st.gateways, domain.Gateway{
		ID: "gw-org2", OrgID: otherOrg, Name: "org2-gateway", Status: "active",
		CredentialHash: identity.HashToken(token),
	})
	cfg := config.Config{
		ServiceName:    "policy-gateway",
		ServiceVersion: "test",
		Identity:       config.AgentIdentity{OrgID: "org-1", UserID: "user-1", AgentID: "agent-1"},
	}
	egress := service.NewEgress(st, policy.NewRuleEngine(st))
	srv := api.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), st, egress, identity.NewService(st))

	req := httptest.NewRequest(http.MethodGet, "/api/internal/v1/policies/snapshot", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("snapshot: status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	var snapshot domain.PolicySnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snapshot); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	// org_id comes from the credential, not from anything the caller sent.
	if snapshot.OrgID != otherOrg {
		t.Fatalf("snapshot org_id = %q, want %q", snapshot.OrgID, otherOrg)
	}
	for _, rule := range snapshot.Rules {
		if rule.OrgID != otherOrg {
			t.Fatalf("snapshot for %s contained a rule from org %q", otherOrg, rule.OrgID)
		}
	}
}

// A gateway must not be able to heartbeat a gateway belonging to another org,
// even by naming a real gateway id.
func TestGatewayHeartbeatRejectsOtherOrgGateway(t *testing.T) {
	token := "clr_gateway_org2-token"
	st := twoOrgFixtures()
	st.gateways = append(st.gateways, domain.Gateway{
		ID: "gw-org2", OrgID: otherOrg, Name: "org2-gateway", Status: "active",
		CredentialHash: identity.HashToken(token),
	})
	cfg := config.Config{
		ServiceName:    "policy-gateway",
		ServiceVersion: "test",
		Identity:       config.AgentIdentity{OrgID: "org-1", UserID: "user-1", AgentID: "agent-1"},
	}
	egress := service.NewEgress(st, policy.NewRuleEngine(st))
	srv := api.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), st, egress, identity.NewService(st))

	// gw-1 is a real gateway, but it belongs to org-1, not this credential's org.
	req := httptest.NewRequest(http.MethodPost, "/api/internal/v1/gateways/gw-1/heartbeat", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("heartbeat other org's gateway: status = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
}

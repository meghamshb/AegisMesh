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

func TestHealthOK(t *testing.T) {
	cfg := config.Config{
		ServiceName:    "policy-gateway",
		ServiceVersion: "test",
	}
	egress := service.NewEgress(stubStore{}, policy.NewRuleEngine(stubStore{}))
	srv := api.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), stubStore{}, egress, identity.NewService(stubStore{}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var payload domain.HealthStatus
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.Status != "ok" {
		t.Fatalf("status = %q, want ok", payload.Status)
	}
}

func testDirectoryFixtures() stubStore {
	return stubStore{
		organization: domain.Organization{ID: "org-1", Slug: "default", Name: "Default Organization", Status: "active"},
		users: []domain.User{
			{ID: "user-1", OrgID: "org-1", DisplayName: "Alice", Role: "member", Status: "active"},
			{ID: "user-2", OrgID: "org-1", DisplayName: "Bob", Role: "member", Status: "disabled"},
		},
		agents: []domain.Agent{
			{ID: "agent-1", OrgID: "org-1", OwnerUserID: "user-1", OwnerDisplayName: "Alice", Name: "alice-macbook-hermes", Status: "active"},
			{ID: "agent-2", OrgID: "org-1", OwnerUserID: "user-2", OwnerDisplayName: "Bob", Name: "bob-windows-hermes", Status: "revoked"},
		},
	}
}

func newDirectoryTestServer(st stubStore) *api.Server {
	cfg := config.Config{
		ServiceName:    "policy-gateway",
		ServiceVersion: "test",
		Identity:       config.AgentIdentity{OrgID: "org-1", UserID: "user-1", AgentID: "agent-1"},
	}
	egress := service.NewEgress(st, policy.NewRuleEngine(st))
	return api.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), st, egress, identity.NewService(st))
}

func TestGetCurrentOrganization(t *testing.T) {
	srv := newDirectoryTestServer(testDirectoryFixtures())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/organizations/current", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var org domain.Organization
	if err := json.Unmarshal(rec.Body.Bytes(), &org); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if org.ID != "org-1" || org.Name != "Default Organization" {
		t.Fatalf("unexpected organization: %+v", org)
	}
}

func TestListUsers(t *testing.T) {
	srv := newDirectoryTestServer(testDirectoryFixtures())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var payload struct {
		Items []domain.User `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(payload.Items) != 2 {
		t.Fatalf("len(items) = %d, want 2", len(payload.Items))
	}
}

func TestListUsersFilterActive(t *testing.T) {
	srv := newDirectoryTestServer(testDirectoryFixtures())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users?status=active", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var payload struct {
		Items []domain.User `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(payload.Items) != 1 || payload.Items[0].DisplayName != "Alice" {
		t.Fatalf("unexpected filtered users: %+v", payload.Items)
	}
}

func TestGetUserNotFound(t *testing.T) {
	srv := newDirectoryTestServer(testDirectoryFixtures())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/does-not-exist", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestListAgents(t *testing.T) {
	srv := newDirectoryTestServer(testDirectoryFixtures())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var payload struct {
		Items []domain.Agent `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(payload.Items) != 2 {
		t.Fatalf("len(items) = %d, want 2", len(payload.Items))
	}
}

func TestListAgentsFilterByUser(t *testing.T) {
	srv := newDirectoryTestServer(testDirectoryFixtures())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents?user_id=user-1", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var payload struct {
		Items []domain.Agent `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(payload.Items) != 1 || payload.Items[0].Name != "alice-macbook-hermes" {
		t.Fatalf("unexpected filtered agents: %+v", payload.Items)
	}
}

func TestGetAgentNotFound(t *testing.T) {
	srv := newDirectoryTestServer(testDirectoryFixtures())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/does-not-exist", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestRegisterAgentReturnsOneTimeToken(t *testing.T) {
	srv := newDirectoryTestServer(testDirectoryFixtures())

	body := `{"owner_user_id":"user-1","name":"alice-macbook-hermes","metadata":{"os":"macos"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Agent      domain.Agent `json:"agent"`
		Credential struct {
			Token       string `json:"token"`
			TokenPrefix string `json:"token_prefix"`
		} `json:"credential"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.Agent.Name != "alice-macbook-hermes" {
		t.Fatalf("agent name = %q, want alice-macbook-hermes", payload.Agent.Name)
	}
	if !strings.HasPrefix(payload.Credential.Token, "clr_agent_") {
		t.Fatalf("credential token = %q, want clr_agent_ prefix", payload.Credential.Token)
	}
	if payload.Credential.TokenPrefix == "" {
		t.Fatal("expected a non-empty token_prefix")
	}
}

func TestRegisterAgentRejectsUnknownOwner(t *testing.T) {
	srv := newDirectoryTestServer(testDirectoryFixtures())

	body := `{"owner_user_id":"does-not-exist","name":"agent-x"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestRegisterAgentRequiresName(t *testing.T) {
	srv := newDirectoryTestServer(testDirectoryFixtures())

	body := `{"owner_user_id":"user-1","name":""}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestRotateAgentCredentialReturnsNewToken(t *testing.T) {
	srv := newDirectoryTestServer(testDirectoryFixtures())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/agent-1/credentials/rotate", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Credential struct {
			Token string `json:"token"`
		} `json:"credential"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !strings.HasPrefix(payload.Credential.Token, "clr_agent_") {
		t.Fatalf("credential token = %q, want clr_agent_ prefix", payload.Credential.Token)
	}
}

func TestRotateAgentCredentialUnknownAgentNotFound(t *testing.T) {
	srv := newDirectoryTestServer(testDirectoryFixtures())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/does-not-exist/credentials/rotate", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestRevokeAgentMarksRevoked(t *testing.T) {
	srv := newDirectoryTestServer(testDirectoryFixtures())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/agent-1/revoke", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	var agent domain.Agent
	if err := json.Unmarshal(rec.Body.Bytes(), &agent); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if agent.Status != "revoked" {
		t.Fatalf("status = %q, want revoked", agent.Status)
	}
}

func TestCreateUser(t *testing.T) {
	srv := newDirectoryTestServer(testDirectoryFixtures())

	body := `{"display_name":"Carol","email":"carol@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}

	var user domain.User
	if err := json.Unmarshal(rec.Body.Bytes(), &user); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if user.DisplayName != "Carol" || user.Role != "member" {
		t.Fatalf("unexpected user: %+v", user)
	}
}

func TestCreateUserRequiresDisplayName(t *testing.T) {
	srv := newDirectoryTestServer(testDirectoryFixtures())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"display_name":""}`))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"bad_request"`) {
		t.Fatalf("expected nested error envelope, got %s", rec.Body.String())
	}
}

func TestUpdateUserDisablesUser(t *testing.T) {
	srv := newDirectoryTestServer(testDirectoryFixtures())

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/users/user-1", strings.NewReader(`{"status":"disabled"}`))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var user domain.User
	if err := json.Unmarshal(rec.Body.Bytes(), &user); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if user.Status != "disabled" {
		t.Fatalf("status = %q, want disabled", user.Status)
	}
}

func TestUpdateUserNotFound(t *testing.T) {
	srv := newDirectoryTestServer(testDirectoryFixtures())

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/users/does-not-exist", strings.NewReader(`{"status":"disabled"}`))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestUpdateAgentRenames(t *testing.T) {
	srv := newDirectoryTestServer(testDirectoryFixtures())

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/agents/agent-1", strings.NewReader(`{"name":"renamed"}`))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var agent domain.Agent
	if err := json.Unmarshal(rec.Body.Bytes(), &agent); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if agent.Name != "renamed" {
		t.Fatalf("name = %q, want renamed", agent.Name)
	}
}

func TestUpdateAgentNotFound(t *testing.T) {
	srv := newDirectoryTestServer(testDirectoryFixtures())

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/agents/does-not-exist", strings.NewReader(`{"name":"x"}`))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestListUsersIncludesPaginationEnvelope(t *testing.T) {
	srv := newDirectoryTestServer(testDirectoryFixtures())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users?limit=1&offset=0", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var payload struct {
		Items      []domain.User `json:"items"`
		Pagination struct {
			Limit    int `json:"limit"`
			Offset   int `json:"offset"`
			Returned int `json:"returned"`
		} `json:"pagination"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.Pagination.Limit != 1 || payload.Pagination.Offset != 0 {
		t.Fatalf("unexpected pagination: %+v", payload.Pagination)
	}
}

func TestListRulesRejectsInvalidActiveParam(t *testing.T) {
	srv := newDirectoryTestServer(testDirectoryFixtures())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules?active=maybe", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestPaginationRejectsInvalidLimit(t *testing.T) {
	srv := newDirectoryTestServer(testDirectoryFixtures())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users?limit=-5", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestRegisterGateway(t *testing.T) {
	srv := newDirectoryTestServer(testDirectoryFixtures())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateways", strings.NewReader(`{"name":"macbook-gateway"}`))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Gateway    domain.Gateway `json:"gateway"`
		Credential struct {
			Token       string `json:"token"`
			TokenPrefix string `json:"token_prefix"`
		} `json:"credential"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.Gateway.Name != "macbook-gateway" {
		t.Fatalf("gateway name = %q, want macbook-gateway", payload.Gateway.Name)
	}
	if !strings.HasPrefix(payload.Credential.Token, "clr_gateway_") {
		t.Fatalf("credential token = %q, want clr_gateway_ prefix", payload.Credential.Token)
	}
}

func TestRegisterGatewayRequiresName(t *testing.T) {
	srv := newDirectoryTestServer(testDirectoryFixtures())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateways", strings.NewReader(`{"name":""}`))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func gatewayFixture(t *testing.T) (stubStore, string) {
	t.Helper()
	token := "clr_gateway_test-token"
	fixtures := testDirectoryFixtures()
	fixtures.gateways = []domain.Gateway{
		{ID: "gw-1", OrgID: "org-1", Name: "macbook-gateway", Status: "active", CredentialHash: identity.HashToken(token)},
		{ID: "gw-revoked", OrgID: "org-1", Name: "old-gateway", Status: "revoked", CredentialHash: identity.HashToken("clr_gateway_revoked-token")},
	}
	return fixtures, token
}

func TestListGateways(t *testing.T) {
	fixtures, _ := gatewayFixture(t)
	srv := newDirectoryTestServer(fixtures)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateways", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var payload struct {
		Items []domain.Gateway `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(payload.Items) != 2 {
		t.Fatalf("len(items) = %d, want 2", len(payload.Items))
	}
}

func TestGatewayHeartbeatRequiresValidCredential(t *testing.T) {
	fixtures, _ := gatewayFixture(t)
	srv := newDirectoryTestServer(fixtures)

	req := httptest.NewRequest(http.MethodPost, "/api/internal/v1/gateways/gw-1/heartbeat", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 without a credential", rec.Code)
	}
}

func TestGatewayHeartbeatSucceedsWithValidCredential(t *testing.T) {
	fixtures, token := gatewayFixture(t)
	srv := newDirectoryTestServer(fixtures)

	req := httptest.NewRequest(http.MethodPost, "/api/internal/v1/gateways/gw-1/heartbeat", strings.NewReader(`{"version":"0.1.0"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestGatewayHeartbeatRejectsMismatchedGatewayID(t *testing.T) {
	fixtures, token := gatewayFixture(t)
	srv := newDirectoryTestServer(fixtures)

	// token belongs to gw-1; heartbeating as a different gateway ID must fail,
	// even though the credential is otherwise valid.
	req := httptest.NewRequest(http.MethodPost, "/api/internal/v1/gateways/some-other-gateway/heartbeat", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestGatewayHeartbeatRejectsRevokedGateway(t *testing.T) {
	fixtures, _ := gatewayFixture(t)
	srv := newDirectoryTestServer(fixtures)

	req := httptest.NewRequest(http.MethodPost, "/api/internal/v1/gateways/gw-revoked/heartbeat", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer clr_gateway_revoked-token")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a revoked gateway credential", rec.Code)
	}
}

func TestPolicySnapshotRequiresGatewayCredential(t *testing.T) {
	fixtures, _ := gatewayFixture(t)
	srv := newDirectoryTestServer(fixtures)

	req := httptest.NewRequest(http.MethodGet, "/api/internal/v1/policies/snapshot", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 without a gateway credential", rec.Code)
	}
}

func TestPolicySnapshotReturnsVersionedRules(t *testing.T) {
	fixtures, token := gatewayFixture(t)
	srv := newDirectoryTestServer(fixtures)

	req := httptest.NewRequest(http.MethodGet, "/api/internal/v1/policies/snapshot", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var snap domain.PolicySnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if snap.OrgID != "org-1" {
		t.Fatalf("org_id = %q, want org-1 (derived from the gateway credential, not client-supplied)", snap.OrgID)
	}
	if snap.Version != 3 {
		t.Fatalf("version = %d, want 3", snap.Version)
	}
	if len(snap.Rules) != 1 {
		t.Fatalf("len(rules) = %d, want 1", len(snap.Rules))
	}
}

func TestInternalAuthenticateAgentRequiresGatewayCredential(t *testing.T) {
	fixtures, _ := gatewayFixture(t)
	srv := newDirectoryTestServer(fixtures)

	req := httptest.NewRequest(http.MethodPost, "/api/internal/v1/agents/authenticate", strings.NewReader(`{"token_hash":"abc"}`))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 without a gateway credential", rec.Code)
	}
}

// Phase 5.10: a gateway learns its own id from its credential, so a fleet
// container does not have to be told its UUID through configuration.
func TestGatewaySelfReturnsTheCredentialsOwnGateway(t *testing.T) {
	fixtures, token := gatewayFixture(t)
	srv := newDirectoryTestServer(fixtures)

	req := httptest.NewRequest(http.MethodGet, "/api/internal/v1/gateways/self", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	var gw domain.Gateway
	if err := json.Unmarshal(rec.Body.Bytes(), &gw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if gw.ID != "gw-1" {
		t.Fatalf("id = %q, want gw-1", gw.ID)
	}
	// The credential hash must never be serialized back to a caller.
	if strings.Contains(rec.Body.String(), "credential_hash") {
		t.Fatalf("gateway self leaked the credential hash: %s", rec.Body.String())
	}
}

func TestGatewaySelfRequiresGatewayCredential(t *testing.T) {
	fixtures, _ := gatewayFixture(t)
	srv := newDirectoryTestServer(fixtures)

	req := httptest.NewRequest(http.MethodGet, "/api/internal/v1/gateways/self", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 without a gateway credential", rec.Code)
	}
}

// A revoked gateway must not be able to resolve itself either - the whole
// point of revocation is that the credential stops working everywhere.
func TestGatewaySelfRejectsRevokedGateway(t *testing.T) {
	fixtures, _ := gatewayFixture(t)
	srv := newDirectoryTestServer(fixtures)

	req := httptest.NewRequest(http.MethodGet, "/api/internal/v1/gateways/self", nil)
	req.Header.Set("Authorization", "Bearer clr_gateway_revoked-token")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a revoked gateway credential", rec.Code)
	}
}

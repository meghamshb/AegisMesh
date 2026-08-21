package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/config"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/identity"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeIdentityStore is a minimal identity.Store fake for exercising the
// proxy's token-mode identity resolution without a real database.
type fakeIdentityStore struct {
	agentsByCredential map[string]domain.Agent // keyed by token hash
	credentials        map[string]domain.AgentCredential
	orgs               map[string]domain.Organization
}

func newFakeIdentityStore() *fakeIdentityStore {
	return &fakeIdentityStore{
		agentsByCredential: map[string]domain.Agent{},
		credentials:        map[string]domain.AgentCredential{},
		orgs:               map[string]domain.Organization{},
	}
}

func (f *fakeIdentityStore) addAgent(tokenHash string, agent domain.Agent, credStatus string) {
	if agent.Status == "" {
		agent.Status = "active"
	}
	f.agentsByCredential[tokenHash] = agent
	f.credentials[tokenHash] = domain.AgentCredential{ID: "cred-" + agent.ID, AgentID: agent.ID, TokenHash: tokenHash, Status: credStatus}
	if _, ok := f.orgs[agent.OrgID]; !ok {
		f.orgs[agent.OrgID] = domain.Organization{ID: agent.OrgID, Status: "active"}
	}
}

func (f *fakeIdentityStore) RegisterAgent(context.Context, store.RegisterAgentInput, store.AuditInput) (domain.Agent, error) {
	return domain.Agent{}, nil
}
func (f *fakeIdentityStore) RevokeAgent(context.Context, string, store.AuditInput) (domain.Agent, error) {
	return domain.Agent{}, nil
}
func (f *fakeIdentityStore) GetAgent(_ context.Context, id string) (domain.Agent, error) {
	for _, a := range f.agentsByCredential {
		if a.ID == id {
			return a, nil
		}
	}
	return domain.Agent{}, domain.ErrNotFound{Resource: "agent", ID: id}
}
func (f *fakeIdentityStore) CreateAgentCredential(context.Context, store.CreateAgentCredentialInput, store.AuditInput) (domain.AgentCredential, error) {
	return domain.AgentCredential{}, nil
}
func (f *fakeIdentityStore) RotateAgentCredential(context.Context, string, store.CreateAgentCredentialInput, store.AuditInput) (domain.AgentCredential, error) {
	return domain.AgentCredential{}, nil
}
func (f *fakeIdentityStore) GetAgentCredentialByHash(_ context.Context, tokenHash string) (domain.AgentCredential, error) {
	cred, ok := f.credentials[tokenHash]
	if !ok {
		return domain.AgentCredential{}, domain.ErrNotFound{Resource: "agent_credential", ID: "token"}
	}
	return cred, nil
}
func (f *fakeIdentityStore) TouchAgentCredentialLastUsed(context.Context, string) error { return nil }
func (f *fakeIdentityStore) TouchAgentLastSeen(context.Context, string) error           { return nil }
func (f *fakeIdentityStore) GetUser(_ context.Context, id string) (domain.User, error) {
	return domain.User{ID: id, Status: "active"}, nil
}

func (f *fakeIdentityStore) RegisterGateway(_ context.Context, in store.RegisterGatewayInput) (domain.Gateway, error) {
	return domain.Gateway{}, nil
}
func (f *fakeIdentityStore) GetGateway(_ context.Context, id string) (domain.Gateway, error) {
	return domain.Gateway{}, nil
}
func (f *fakeIdentityStore) GetGatewayByCredentialHash(_ context.Context, hash string) (domain.Gateway, error) {
	return domain.Gateway{}, nil
}
func (f *fakeIdentityStore) UpdateGatewayHeartbeat(_ context.Context, id string, _ store.GatewayHeartbeatInput) (domain.Gateway, error) {
	return domain.Gateway{}, nil
}

func (f *fakeIdentityStore) GetOrganization(_ context.Context, id string) (domain.Organization, error) {
	org, ok := f.orgs[id]
	if !ok {
		return domain.Organization{}, domain.ErrNotFound{Resource: "organization", ID: id}
	}
	return org, nil
}

func newTokenModeHandler(st *fakeIdentityStore) *Handler {
	return &Handler{
		enabled:     true,
		authMode:    config.AgentAuthModeToken,
		identitySvc: identity.NewService(st),
		logger:      testLogger(),
	}
}

func TestResolveIdentityTokenModeSuccess(t *testing.T) {
	st := newFakeIdentityStore()
	tokenHash := identity.HashAgentToken("clr_agent_agent-a-token")
	st.addAgent(tokenHash, domain.Agent{ID: "agent-a", OrgID: "org-1", OwnerUserID: "alice"}, "active")

	h := newTokenModeHandler(st)
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("Proxy-Authorization", "Bearer clr_agent_agent-a-token")

	got, err := h.resolveIdentity(r)
	if err != nil {
		t.Fatalf("resolveIdentity() error = %v", err)
	}
	if got.AgentID != "agent-a" || got.UserID != "alice" || got.OrgID != "org-1" {
		t.Fatalf("unexpected identity: %+v", got)
	}
}

func TestResolveIdentityTokenModeDistinctAgents(t *testing.T) {
	st := newFakeIdentityStore()
	hashA := identity.HashAgentToken("clr_agent_token-a")
	hashB := identity.HashAgentToken("clr_agent_token-b")
	st.addAgent(hashA, domain.Agent{ID: "agent-a", OrgID: "org-1", OwnerUserID: "alice"}, "active")
	st.addAgent(hashB, domain.Agent{ID: "agent-b", OrgID: "org-1", OwnerUserID: "bob"}, "active")

	h := newTokenModeHandler(st)

	reqA := httptest.NewRequest("GET", "http://example.com/", nil)
	reqA.Header.Set("Proxy-Authorization", "Bearer clr_agent_token-a")
	identityA, err := h.resolveIdentity(reqA)
	if err != nil {
		t.Fatalf("resolveIdentity(A) error = %v", err)
	}

	reqB := httptest.NewRequest("GET", "http://example.com/", nil)
	reqB.Header.Set("Proxy-Authorization", "Bearer clr_agent_token-b")
	identityB, err := h.resolveIdentity(reqB)
	if err != nil {
		t.Fatalf("resolveIdentity(B) error = %v", err)
	}

	if identityA.AgentID == identityB.AgentID {
		t.Fatal("expected distinct agent identities for distinct tokens")
	}
	if identityA.UserID != "alice" || identityB.UserID != "bob" {
		t.Fatalf("unexpected owners: A=%+v B=%+v", identityA, identityB)
	}
}

func TestResolveIdentityTokenModeCannotImpersonateViaOverrideHeader(t *testing.T) {
	st := newFakeIdentityStore()
	hashA := identity.HashAgentToken("clr_agent_token-a")
	st.addAgent(hashA, domain.Agent{ID: "agent-a", OrgID: "org-1", OwnerUserID: "alice"}, "active")

	h := newTokenModeHandler(st)
	h.allowIdentityOverride = true
	h.agentIDHeader = "X-Gateway-Agent-Id"

	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("Proxy-Authorization", "Bearer clr_agent_token-a")
	r.Header.Set("X-Gateway-Agent-Id", "agent-b")

	got, err := h.resolveIdentity(r)
	if err != nil {
		t.Fatalf("resolveIdentity() error = %v", err)
	}
	if got.AgentID != "agent-a" {
		t.Fatalf("agent ID = %q, want agent-a (override header must be ignored in token mode)", got.AgentID)
	}
}

func TestResolveIdentityTokenModeMissingToken(t *testing.T) {
	h := newTokenModeHandler(newFakeIdentityStore())
	r := httptest.NewRequest("GET", "http://example.com/", nil)

	_, err := h.resolveIdentity(r)
	if !errors.Is(err, identity.ErrInvalidToken) {
		t.Fatalf("error = %v, want ErrInvalidToken", err)
	}
}

func TestResolveIdentityTokenModeRandomToken(t *testing.T) {
	h := newTokenModeHandler(newFakeIdentityStore())
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("Proxy-Authorization", "Bearer clr_agent_totally-made-up")

	_, err := h.resolveIdentity(r)
	if !errors.Is(err, identity.ErrInvalidToken) {
		t.Fatalf("error = %v, want ErrInvalidToken", err)
	}
}

func TestResolveIdentityTokenModeRevokedCredential(t *testing.T) {
	st := newFakeIdentityStore()
	hash := identity.HashAgentToken("clr_agent_revoked-token")
	st.addAgent(hash, domain.Agent{ID: "agent-a", OrgID: "org-1", OwnerUserID: "alice"}, "revoked")

	h := newTokenModeHandler(st)
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("Proxy-Authorization", "Bearer clr_agent_revoked-token")

	_, err := h.resolveIdentity(r)
	if !errors.Is(err, identity.ErrCredentialRevoked) {
		t.Fatalf("error = %v, want ErrCredentialRevoked", err)
	}
}

func TestResolveIdentityTokenModeRevokedAgent(t *testing.T) {
	st := newFakeIdentityStore()
	hash := identity.HashAgentToken("clr_agent_token-revoked-agent")
	st.addAgent(hash, domain.Agent{ID: "agent-a", OrgID: "org-1", OwnerUserID: "alice", Status: "revoked"}, "active")

	h := newTokenModeHandler(st)
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("Proxy-Authorization", "Bearer clr_agent_token-revoked-agent")

	_, err := h.resolveIdentity(r)
	if !errors.Is(err, identity.ErrAgentRevoked) {
		t.Fatalf("error = %v, want ErrAgentRevoked", err)
	}
}

func TestExtractProxyTokenBearer(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("Proxy-Authorization", "Bearer clr_agent_abc123")

	token, ok := extractProxyToken(r)
	if !ok || token != "clr_agent_abc123" {
		t.Fatalf("token = %q, ok = %v", token, ok)
	}
}

func TestExtractProxyTokenBasic(t *testing.T) {
	creds := base64.StdEncoding.EncodeToString([]byte("agent:clr_agent_abc123"))
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("Proxy-Authorization", "Basic "+creds)

	token, ok := extractProxyToken(r)
	if !ok || token != "clr_agent_abc123" {
		t.Fatalf("token = %q, ok = %v", token, ok)
	}
}

func TestExtractProxyTokenMissing(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	if _, ok := extractProxyToken(r); ok {
		t.Fatal("expected ok = false for missing header")
	}
}

func TestForwardHTTPStripsProxyAuthorization(t *testing.T) {
	var gotAuth, gotConn string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Proxy-Authorization")
		gotConn = r.Header.Get("Proxy-Connection")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	h := &Handler{
		logger:    testLogger(),
		transport: &http.Transport{},
	}

	req := httptest.NewRequest(http.MethodGet, upstream.URL, nil)
	req.Header.Set("Proxy-Authorization", "Bearer clr_agent_should-not-leak")
	req.Header.Set("Proxy-Connection", "keep-alive")
	rec := httptest.NewRecorder()

	h.forwardHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotAuth != "" {
		t.Fatalf("upstream received Proxy-Authorization = %q, want empty", gotAuth)
	}
	if gotConn != "" {
		t.Fatalf("upstream received Proxy-Connection = %q, want empty", gotConn)
	}
}

// fakeRemoteAgentAuth is a minimal remoteAgentAuthenticator fake proving
// resolveTokenIdentity uses the remote (fleet-mode) path when configured,
// instead of identitySvc's direct-DB path.
type fakeRemoteAgentAuth struct {
	byHash map[string]config.AgentIdentity
	calls  int
}

func (f *fakeRemoteAgentAuth) Authenticate(_ context.Context, tokenHash string) (config.AgentIdentity, error) {
	f.calls++
	id, ok := f.byHash[tokenHash]
	if !ok {
		return config.AgentIdentity{}, identity.ErrInvalidToken
	}
	return id, nil
}

func TestResolveIdentityUsesRemoteAuthWhenConfigured(t *testing.T) {
	hashA := identity.HashAgentToken("clr_agent_remote-token-a")
	remote := &fakeRemoteAgentAuth{byHash: map[string]config.AgentIdentity{
		hashA: {OrgID: "org-1", UserID: "alice", AgentID: "agent-a"},
	}}

	h := &Handler{
		enabled:         true,
		authMode:        config.AgentAuthModeToken,
		remoteAgentAuth: remote,
		// identitySvc deliberately left nil: if resolveTokenIdentity fell
		// through to the direct-DB path it would nil-panic, proving remote
		// really is used instead.
		logger: testLogger(),
	}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Proxy-Authorization", "Bearer clr_agent_remote-token-a")

	got, err := h.resolveIdentity(req)
	if err != nil {
		t.Fatalf("resolveIdentity() error = %v", err)
	}
	if got.AgentID != "agent-a" || got.UserID != "alice" || got.OrgID != "org-1" {
		t.Fatalf("unexpected identity: %+v", got)
	}
	if remote.calls != 1 {
		t.Fatalf("expected remote auth to be called once, got %d", remote.calls)
	}
}

func TestResolveIdentityRemoteAuthInvalidToken(t *testing.T) {
	remote := &fakeRemoteAgentAuth{byHash: map[string]config.AgentIdentity{}}
	h := &Handler{
		enabled:         true,
		authMode:        config.AgentAuthModeToken,
		remoteAgentAuth: remote,
		logger:          testLogger(),
	}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Proxy-Authorization", "Bearer clr_agent_unknown-token")

	_, err := h.resolveIdentity(req)
	if !errors.Is(err, identity.ErrInvalidToken) {
		t.Fatalf("error = %v, want ErrInvalidToken", err)
	}
}

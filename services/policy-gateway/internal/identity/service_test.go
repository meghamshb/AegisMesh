package identity_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"testing"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/identity"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store/storetest"
)

type fakeStore struct {
	storetest.Stub
	agents      map[string]domain.Agent
	credentials map[string]domain.AgentCredential // keyed by token hash
	orgStatus   string                            // empty means "active"
	ownerStatus string                            // empty means "active"
	nextID      int
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		agents:      map[string]domain.Agent{},
		credentials: map[string]domain.AgentCredential{},
	}
}

func (f *fakeStore) genID(prefix string) string {
	f.nextID++
	return prefix + "-" + strconv.Itoa(f.nextID)
}

func (f *fakeStore) RegisterAgent(_ context.Context, in store.RegisterAgentInput, _ store.AuditInput) (domain.Agent, error) {
	agent := domain.Agent{
		ID:          f.genID("agent"),
		OrgID:       in.OrgID,
		OwnerUserID: in.OwnerUserID,
		Name:        in.Name,
		Status:      "active",
	}
	f.agents[agent.ID] = agent
	return agent, nil
}

func (f *fakeStore) RevokeAgent(_ context.Context, orgID, agentID string, _ store.AuditInput) (domain.Agent, error) {
	agent, ok := f.agents[agentID]
	if !ok || agent.OrgID != orgID {
		return domain.Agent{}, domain.ErrNotFound{Resource: "agent", ID: agentID}
	}
	agent.Status = "revoked"
	f.agents[agentID] = agent
	for hash, cred := range f.credentials {
		if cred.AgentID == agentID {
			cred.Status = "revoked"
			f.credentials[hash] = cred
		}
	}
	return agent, nil
}

func (f *fakeStore) GetAgent(_ context.Context, orgID, id string) (domain.Agent, error) {
	agent, ok := f.agents[id]
	if !ok || agent.OrgID != orgID {
		return domain.Agent{}, domain.ErrNotFound{Resource: "agent", ID: id}
	}
	return agent, nil
}

// ResolveAgentForAuth is the deliberately un-org-scoped variant used inside
// authentication, mirroring the real store.
func (f *fakeStore) ResolveAgentForAuth(_ context.Context, id string) (domain.Agent, error) {
	agent, ok := f.agents[id]
	if !ok {
		return domain.Agent{}, domain.ErrNotFound{Resource: "agent", ID: id}
	}
	return agent, nil
}

func (f *fakeStore) CreateAgentCredential(_ context.Context, in store.CreateAgentCredentialInput, _ store.AuditInput) (domain.AgentCredential, error) {
	cred := domain.AgentCredential{
		ID:          f.genID("cred"),
		AgentID:     in.AgentID,
		TokenPrefix: in.TokenPrefix,
		TokenHash:   in.TokenHash,
		Status:      "active",
	}
	f.credentials[in.TokenHash] = cred
	return cred, nil
}

func (f *fakeStore) RotateAgentCredential(_ context.Context, orgID, agentID string, in store.CreateAgentCredentialInput, _ store.AuditInput) (domain.AgentCredential, error) {
	if agent, ok := f.agents[agentID]; !ok || agent.OrgID != orgID {
		return domain.AgentCredential{}, domain.ErrNotFound{Resource: "agent", ID: agentID}
	}
	for hash, cred := range f.credentials {
		if cred.AgentID == agentID && cred.Status == "active" {
			cred.Status = "revoked"
			f.credentials[hash] = cred
		}
	}
	cred := domain.AgentCredential{
		ID:          f.genID("cred"),
		AgentID:     agentID,
		TokenPrefix: in.TokenPrefix,
		TokenHash:   in.TokenHash,
		Status:      "active",
	}
	f.credentials[in.TokenHash] = cred
	return cred, nil
}

func (f *fakeStore) GetAgentCredentialByHash(_ context.Context, tokenHash string) (domain.AgentCredential, error) {
	cred, ok := f.credentials[tokenHash]
	if !ok {
		return domain.AgentCredential{}, domain.ErrNotFound{Resource: "agent_credential", ID: "token"}
	}
	return cred, nil
}

func (f *fakeStore) TouchAgentCredentialLastUsed(_ context.Context, _ string) error {
	return nil
}

func (f *fakeStore) TouchAgentLastSeen(_ context.Context, _ string) error {
	return nil
}

func (f *fakeStore) GetUser(_ context.Context, orgID, id string) (domain.User, error) {
	status := f.ownerStatus
	if status == "" {
		status = "active"
	}
	return domain.User{ID: id, OrgID: orgID, Status: status}, nil
}

func (f *fakeStore) GetOrganization(_ context.Context, id string) (domain.Organization, error) {
	status := f.orgStatus
	if status == "" {
		status = "active"
	}
	return domain.Organization{ID: id, Status: status}, nil
}

func TestRegisterAgentIssuesCredentialOnce(t *testing.T) {
	svc := identity.NewService(newFakeStore())

	agent, token, cred, err := svc.RegisterAgent(context.Background(), identity.RegisterAgentInput{
		OrgID:       "org-1",
		OwnerUserID: "user-1",
		Name:        "alice-macbook-hermes",
	}, "admin-1")
	if err != nil {
		t.Fatalf("RegisterAgent() error = %v", err)
	}
	if agent.Name != "alice-macbook-hermes" {
		t.Fatalf("agent name = %q, want alice-macbook-hermes", agent.Name)
	}
	if token == "" || cred.ID == "" {
		t.Fatal("expected a non-empty token and credential")
	}
	if identity.HashAgentToken(token) != cred.TokenHash {
		t.Fatal("returned token does not hash to the stored credential hash")
	}
}

func TestAuthenticateAgentTokenSuccess(t *testing.T) {
	st := newFakeStore()
	svc := identity.NewService(st)

	_, token, _, err := svc.RegisterAgent(context.Background(), identity.RegisterAgentInput{
		OrgID: "org-1", OwnerUserID: "user-1", Name: "agent-a",
	}, "admin-1")
	if err != nil {
		t.Fatalf("RegisterAgent() error = %v", err)
	}

	authed, err := svc.AuthenticateAgentToken(context.Background(), token)
	if err != nil {
		t.Fatalf("AuthenticateAgentToken() error = %v", err)
	}
	if authed.OrgID != "org-1" || authed.OwnerUserID != "user-1" {
		t.Fatalf("unexpected identity: %+v", authed)
	}
}

func TestAuthenticateAgentTokenInvalid(t *testing.T) {
	svc := identity.NewService(newFakeStore())

	_, err := svc.AuthenticateAgentToken(context.Background(), "clr_agent_not-a-real-token")
	if !errors.Is(err, identity.ErrInvalidToken) {
		t.Fatalf("error = %v, want ErrInvalidToken", err)
	}
}

func TestRotateCredentialRejectsOldAcceptsNew(t *testing.T) {
	st := newFakeStore()
	svc := identity.NewService(st)

	agent, oldToken, _, err := svc.RegisterAgent(context.Background(), identity.RegisterAgentInput{
		OrgID: "org-1", OwnerUserID: "user-1", Name: "agent-a",
	}, "admin-1")
	if err != nil {
		t.Fatalf("RegisterAgent() error = %v", err)
	}

	newToken, _, err := svc.RotateCredential(context.Background(), agent.OrgID, agent.ID, "admin-1")
	if err != nil {
		t.Fatalf("RotateCredential() error = %v", err)
	}

	if _, err := svc.AuthenticateAgentToken(context.Background(), oldToken); !errors.Is(err, identity.ErrCredentialRevoked) {
		t.Fatalf("old token error = %v, want ErrCredentialRevoked", err)
	}
	if _, err := svc.AuthenticateAgentToken(context.Background(), newToken); err != nil {
		t.Fatalf("new token should authenticate: %v", err)
	}
}

func TestRevokeAgentRejectsNewToken(t *testing.T) {
	st := newFakeStore()
	svc := identity.NewService(st)

	agent, token, _, err := svc.RegisterAgent(context.Background(), identity.RegisterAgentInput{
		OrgID: "org-1", OwnerUserID: "user-1", Name: "agent-a",
	}, "admin-1")
	if err != nil {
		t.Fatalf("RegisterAgent() error = %v", err)
	}

	if _, err := svc.RevokeAgent(context.Background(), agent.OrgID, agent.ID, "admin-1"); err != nil {
		t.Fatalf("RevokeAgent() error = %v", err)
	}

	if _, err := svc.AuthenticateAgentToken(context.Background(), token); !errors.Is(err, identity.ErrCredentialRevoked) {
		t.Fatalf("error = %v, want ErrCredentialRevoked", err)
	}
}

func TestAuthenticateAgentTokenOrgSuspended(t *testing.T) {
	st := newFakeStore()
	svc := identity.NewService(st)

	_, token, _, err := svc.RegisterAgent(context.Background(), identity.RegisterAgentInput{
		OrgID: "org-1", OwnerUserID: "user-1", Name: "agent-a",
	}, "admin-1")
	if err != nil {
		t.Fatalf("RegisterAgent() error = %v", err)
	}

	st.orgStatus = "suspended"

	if _, err := svc.AuthenticateAgentToken(context.Background(), token); !errors.Is(err, identity.ErrOrgSuspended) {
		t.Fatalf("error = %v, want ErrOrgSuspended", err)
	}
}

func TestAuthenticateAgentTokenOwnerDisabled(t *testing.T) {
	st := newFakeStore()
	svc := identity.NewService(st)

	_, token, _, err := svc.RegisterAgent(context.Background(), identity.RegisterAgentInput{
		OrgID: "org-1", OwnerUserID: "user-1", Name: "agent-a",
	}, "admin-1")
	if err != nil {
		t.Fatalf("RegisterAgent() error = %v", err)
	}

	// Disabling the owning human user must cascade: their agent's credential
	// stops authenticating even though the credential and agent themselves
	// were never individually revoked (Phase 5.6.3).
	st.ownerStatus = "disabled"

	if _, err := svc.AuthenticateAgentToken(context.Background(), token); !errors.Is(err, identity.ErrOwnerDisabled) {
		t.Fatalf("error = %v, want ErrOwnerDisabled", err)
	}
}

// last_used_at and last_seen_at are display-only - nothing reads them for a
// decision. A failure to write them must not take an agent offline: a
// read-only replica or a full disk would otherwise stop all egress while the
// credential is perfectly valid and policy is still evaluable.
type touchFailingStore struct {
	*fakeStore
	touchErr error
}

func (f *touchFailingStore) TouchAgentCredentialLastUsed(context.Context, string) error {
	return f.touchErr
}

func (f *touchFailingStore) TouchAgentLastSeen(context.Context, string) error {
	return f.touchErr
}

func TestBookkeepingFailureDoesNotBreakAuthentication(t *testing.T) {
	base := newFakeStore()
	st := &touchFailingStore{fakeStore: base, touchErr: errors.New("read-only transaction")}
	svc := identity.NewService(st).WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))

	agent, token, _, err := svc.RegisterAgent(context.Background(), identity.RegisterAgentInput{
		OrgID:       "org-1",
		OwnerUserID: "user-1",
		Name:        "bookkeeping-agent",
	}, "admin-1")
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	authed, err := svc.AuthenticateAgentToken(context.Background(), token)
	if err != nil {
		t.Fatalf("authentication failed because a timestamp could not be written: %v", err)
	}
	if authed.AgentID != agent.ID {
		t.Fatalf("AgentID = %q, want %q", authed.AgentID, agent.ID)
	}
}

// A genuinely revoked credential must still be refused - the change above
// relaxes bookkeeping, not the security checks around it.
func TestRevokedCredentialStillRefusedWhenBookkeepingFails(t *testing.T) {
	base := newFakeStore()
	st := &touchFailingStore{fakeStore: base, touchErr: errors.New("read-only transaction")}
	svc := identity.NewService(st).WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))

	agent, token, _, err := svc.RegisterAgent(context.Background(), identity.RegisterAgentInput{
		OrgID: "org-1", OwnerUserID: "user-1", Name: "to-revoke",
	}, "admin-1")
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	if _, err := svc.RevokeAgent(context.Background(), agent.OrgID, agent.ID, "admin-1"); err != nil {
		t.Fatalf("RevokeAgent: %v", err)
	}

	if _, err := svc.AuthenticateAgentToken(context.Background(), token); err == nil {
		t.Fatal("a revoked credential authenticated successfully")
	}
}

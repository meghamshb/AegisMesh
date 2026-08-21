package app_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/app"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/config"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
)

// noopStore is a minimal store.Store fake: every method returns a zero
// value. It exists only to prove HTTP-surface separation between
// ControlHandler and ProxyHandler; no test here exercises real business
// logic (that's covered in internal/api, internal/proxy, internal/service).
type noopStore struct{}

func (noopStore) Ping(context.Context) error { return nil }
func (noopStore) ListRequests(context.Context, store.ListRequestsInput) ([]domain.EgressRequest, error) {
	return nil, nil
}
func (noopStore) ListRules(context.Context, store.ListRulesInput) ([]domain.PolicyRule, error) {
	return nil, nil
}
func (noopStore) ListAuditEvents(context.Context, store.ListAuditEventsInput) ([]domain.AuditEvent, error) {
	return nil, nil
}
func (noopStore) MatchRules(context.Context, store.MatchRulesInput) ([]domain.PolicyRule, error) {
	return nil, nil
}
func (noopStore) CreateEgressRequest(context.Context, store.CreateEgressRequestInput) (domain.EgressRequest, error) {
	return domain.EgressRequest{}, nil
}
func (noopStore) InsertAuditEvent(context.Context, string, string, string, map[string]any) error {
	return nil
}
func (noopStore) GetEgressRequest(context.Context, string) (domain.EgressRequest, error) {
	return domain.EgressRequest{}, nil
}
func (noopStore) ApproveRequestOnce(context.Context, string, string, store.AuditInput) (domain.EgressRequest, error) {
	return domain.EgressRequest{}, nil
}
func (noopStore) ApproveRequestWithScopedRule(context.Context, string, string, domain.RuleScope, string, store.OrgRuleOptions, store.AuditInput) (domain.EgressRequest, domain.PolicyRule, error) {
	return domain.EgressRequest{}, domain.PolicyRule{}, nil
}
func (noopStore) CreatePolicyRule(context.Context, store.CreatePolicyRuleInput, store.AuditInput) (domain.PolicyRule, error) {
	return domain.PolicyRule{}, nil
}
func (noopStore) DeletePolicyRule(context.Context, string, store.AuditInput) error { return nil }
func (noopStore) DenyRequest(context.Context, string, string, string, store.AuditInput) (domain.EgressRequest, error) {
	return domain.EgressRequest{}, nil
}
func (noopStore) FindConsumableApproval(context.Context, store.ApprovalMatchInput) (*domain.EgressRequest, error) {
	return nil, nil
}
func (noopStore) HasDeniedPattern(context.Context, store.ApprovalMatchInput) (bool, error) {
	return false, nil
}
func (noopStore) MarkApprovalConsumed(context.Context, string) error { return nil }
func (noopStore) GetOrganization(context.Context, string) (domain.Organization, error) {
	return domain.Organization{}, nil
}
func (noopStore) ListUsers(context.Context, store.ListUsersInput) ([]domain.User, error) {
	return nil, nil
}
func (noopStore) GetUser(context.Context, string) (domain.User, error) { return domain.User{}, nil }
func (noopStore) CreateUser(context.Context, store.CreateUserInput) (domain.User, error) {
	return domain.User{}, nil
}
func (noopStore) UpdateUser(context.Context, string, store.UpdateUserInput) (domain.User, error) {
	return domain.User{}, nil
}
func (noopStore) ListAgents(context.Context, store.ListAgentsInput) ([]domain.Agent, error) {
	return nil, nil
}
func (noopStore) GetAgent(context.Context, string) (domain.Agent, error) { return domain.Agent{}, nil }
func (noopStore) UpdateAgent(context.Context, string, store.UpdateAgentInput) (domain.Agent, error) {
	return domain.Agent{}, nil
}
func (noopStore) RegisterAgent(context.Context, store.RegisterAgentInput, store.AuditInput) (domain.Agent, error) {
	return domain.Agent{}, nil
}
func (noopStore) RevokeAgent(context.Context, string, store.AuditInput) (domain.Agent, error) {
	return domain.Agent{}, nil
}
func (noopStore) CreateAgentCredential(context.Context, store.CreateAgentCredentialInput, store.AuditInput) (domain.AgentCredential, error) {
	return domain.AgentCredential{}, nil
}
func (noopStore) RotateAgentCredential(context.Context, string, store.CreateAgentCredentialInput, store.AuditInput) (domain.AgentCredential, error) {
	return domain.AgentCredential{}, nil
}
func (noopStore) GetAgentCredentialByHash(context.Context, string) (domain.AgentCredential, error) {
	return domain.AgentCredential{}, nil
}
func (noopStore) TouchAgentCredentialLastUsed(context.Context, string) error { return nil }
func (noopStore) TouchAgentLastSeen(context.Context, string) error           { return nil }

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

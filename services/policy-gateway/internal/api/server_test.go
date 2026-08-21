package api_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/api"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/config"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/policy"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/service"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
)

type stubStore struct {
	organization domain.Organization
	users        []domain.User
	agents       []domain.Agent
}

func (stubStore) Ping(_ context.Context) error { return nil }

func (stubStore) ListRequests(_ context.Context, _ store.ListRequestsInput) ([]domain.EgressRequest, error) {
	return []domain.EgressRequest{}, nil
}

func (stubStore) ListRules(_ context.Context) ([]domain.PolicyRule, error) {
	return []domain.PolicyRule{}, nil
}

func (stubStore) ListAuditEvents(_ context.Context) ([]domain.AuditEvent, error) {
	return []domain.AuditEvent{}, nil
}

func (stubStore) MatchRules(_ context.Context, _ store.MatchRulesInput) ([]domain.PolicyRule, error) {
	return nil, nil
}

func (stubStore) CreateEgressRequest(_ context.Context, _ store.CreateEgressRequestInput) (domain.EgressRequest, error) {
	return domain.EgressRequest{ID: "test-id", Status: domain.RequestStatusPending}, nil
}

func (stubStore) InsertAuditEvent(_ context.Context, _, _, _ string, _ map[string]any) error {
	return nil
}

func (stubStore) GetEgressRequest(_ context.Context, _ string) (domain.EgressRequest, error) {
	return domain.EgressRequest{}, nil
}

func (stubStore) ApproveRequestOnce(_ context.Context, _, _ string, _ store.AuditInput) (domain.EgressRequest, error) {
	return domain.EgressRequest{}, nil
}

func (stubStore) ApproveRequestWithOrgRule(_ context.Context, _, _ string, _ store.OrgRuleOptions, _ store.AuditInput) (domain.EgressRequest, domain.PolicyRule, error) {
	return domain.EgressRequest{}, domain.PolicyRule{}, nil
}

func (stubStore) CreatePolicyRule(_ context.Context, _ store.CreatePolicyRuleInput, _ store.AuditInput) (domain.PolicyRule, error) {
	return domain.PolicyRule{}, nil
}

func (stubStore) DeletePolicyRule(_ context.Context, _ string, _ store.AuditInput) error {
	return nil
}

func (stubStore) DenyRequest(_ context.Context, _, _, _ string, _ store.AuditInput) (domain.EgressRequest, error) {
	return domain.EgressRequest{}, nil
}

func (stubStore) FindConsumableApproval(_ context.Context, _ store.ApprovalMatchInput) (*domain.EgressRequest, error) {
	return nil, nil
}

func (stubStore) HasDeniedPattern(_ context.Context, _ store.ApprovalMatchInput) (bool, error) {
	return false, nil
}

func (stubStore) MarkApprovalConsumed(_ context.Context, _ string) error {
	return nil
}

func (s stubStore) GetOrganization(_ context.Context, id string) (domain.Organization, error) {
	if s.organization.ID != id {
		return domain.Organization{}, domain.ErrNotFound{Resource: "organization", ID: id}
	}
	return s.organization, nil
}

func (s stubStore) ListUsers(_ context.Context, in store.ListUsersInput) ([]domain.User, error) {
	if in.Status == "" {
		return s.users, nil
	}
	filtered := make([]domain.User, 0)
	for _, u := range s.users {
		if u.Status == in.Status {
			filtered = append(filtered, u)
		}
	}
	return filtered, nil
}

func (s stubStore) GetUser(_ context.Context, id string) (domain.User, error) {
	for _, u := range s.users {
		if u.ID == id {
			return u, nil
		}
	}
	return domain.User{}, domain.ErrNotFound{Resource: "user", ID: id}
}

func (s stubStore) ListAgents(_ context.Context, in store.ListAgentsInput) ([]domain.Agent, error) {
	filtered := make([]domain.Agent, 0)
	for _, a := range s.agents {
		if in.UserID != "" && a.OwnerUserID != in.UserID {
			continue
		}
		if in.Status != "" && a.Status != in.Status {
			continue
		}
		filtered = append(filtered, a)
	}
	return filtered, nil
}

func (s stubStore) GetAgent(_ context.Context, id string) (domain.Agent, error) {
	for _, a := range s.agents {
		if a.ID == id {
			return a, nil
		}
	}
	return domain.Agent{}, domain.ErrNotFound{Resource: "agent", ID: id}
}

func TestHealthOK(t *testing.T) {
	cfg := config.Config{
		ServiceName:    "policy-gateway",
		ServiceVersion: "test",
	}
	egress := service.NewEgress(stubStore{}, policy.NewRuleEngine(stubStore{}))
	srv := api.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), stubStore{}, egress)

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
	return api.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), st, egress)
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

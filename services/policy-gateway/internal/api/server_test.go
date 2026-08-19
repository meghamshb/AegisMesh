package api_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/api"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/config"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/policy"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/service"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/store"
)

type stubStore struct{}

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

package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/policy"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/service"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/store"
)

type approvalStore struct {
	approvedOnce    domain.EgressRequest
	approvedWithOrg domain.EgressRequest
	orgRule         domain.PolicyRule
	auditEvents     []string
}

func (s *approvalStore) Ping(context.Context) error { return nil }
func (s *approvalStore) ListRequests(context.Context, store.ListRequestsInput) ([]domain.EgressRequest, error) {
	return nil, nil
}
func (s *approvalStore) ListRules(context.Context) ([]domain.PolicyRule, error) { return nil, nil }
func (s *approvalStore) ListAuditEvents(context.Context) ([]domain.AuditEvent, error) {
	return nil, nil
}
func (s *approvalStore) MatchRules(context.Context, store.MatchRulesInput) ([]domain.PolicyRule, error) {
	return nil, nil
}
func (s *approvalStore) CreateEgressRequest(context.Context, store.CreateEgressRequestInput) (domain.EgressRequest, error) {
	return domain.EgressRequest{}, nil
}
func (s *approvalStore) InsertAuditEvent(_ context.Context, _, eventType, _ string, _ map[string]any) error {
	s.auditEvents = append(s.auditEvents, eventType)
	return nil
}
func (s *approvalStore) GetEgressRequest(context.Context, string) (domain.EgressRequest, error) {
	return domain.EgressRequest{}, nil
}
func (s *approvalStore) ApproveRequestOnce(_ context.Context, _, _ string, audit store.AuditInput) (domain.EgressRequest, error) {
	s.auditEvents = append(s.auditEvents, audit.EventType)
	return s.approvedOnce, nil
}
func (s *approvalStore) ApproveRequestWithOrgRule(_ context.Context, _, _ string, audit store.AuditInput) (domain.EgressRequest, domain.PolicyRule, error) {
	s.auditEvents = append(s.auditEvents, audit.EventType)
	return s.approvedWithOrg, s.orgRule, nil
}
func (s *approvalStore) DeletePolicyRule(context.Context, string, store.AuditInput) error { return nil }
func (s *approvalStore) DenyRequest(context.Context, string, string, string, store.AuditInput) (domain.EgressRequest, error) {
	return domain.EgressRequest{}, nil
}
func (s *approvalStore) FindConsumableApproval(context.Context, store.ApprovalMatchInput) (*domain.EgressRequest, error) {
	return nil, nil
}
func (s *approvalStore) HasDeniedPattern(context.Context, store.ApprovalMatchInput) (bool, error) {
	return false, nil
}
func (s *approvalStore) MarkApprovalConsumed(context.Context, string) error { return nil }

func TestApproveOnceUsesOnceAuditEvent(t *testing.T) {
	st := &approvalStore{
		approvedOnce: domain.EgressRequest{ID: "req-1", Host: "example.com", Port: 443, Method: "GET", Path: "/"},
	}
	svc := service.NewEgress(st, policy.NewRuleEngine(st))

	approved, err := svc.Approve(context.Background(), "req-1", "admin-1", domain.ApproveRequestBody{})
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if approved.ID != "req-1" {
		t.Fatalf("approved ID = %q, want req-1", approved.ID)
	}
	if len(st.auditEvents) != 1 || st.auditEvents[0] != "egress_approved_once" {
		t.Fatalf("audit events = %v, want [egress_approved_once]", st.auditEvents)
	}
}

func TestApproveRememberCreatesOrgRuleAuditEvent(t *testing.T) {
	ruleID := "rule-1"
	st := &approvalStore{
		approvedWithOrg: domain.EgressRequest{ID: "req-2", Host: "api.github.com", Port: 443, Method: "GET", Path: "/zen"},
		orgRule:         domain.PolicyRule{ID: ruleID, PathPrefix: "/zen"},
	}
	svc := service.NewEgress(rememberAuditStore{approvalStore: st, pending: domain.EgressRequest{
		ID: "req-2", Method: "GET", Host: "api.github.com",
	}}, policy.NewRuleEngine(st))

	approved, err := svc.Approve(context.Background(), "req-2", "admin-1", domain.ApproveRequestBody{
		Remember: true,
		Scope:    domain.RuleScopeOrg,
	})
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if approved.ID != "req-2" {
		t.Fatalf("approved ID = %q, want req-2", approved.ID)
	}
	if len(st.auditEvents) != 1 || st.auditEvents[0] != "egress_approved_org_rule" {
		t.Fatalf("audit events = %v, want [egress_approved_org_rule]", st.auditEvents)
	}
}

type rememberAuditStore struct {
	*approvalStore
	pending domain.EgressRequest
}

func (s rememberAuditStore) GetEgressRequest(context.Context, string) (domain.EgressRequest, error) {
	return s.pending, nil
}

type rememberStore struct {
	pending domain.EgressRequest
}

func (rememberStore) Ping(context.Context) error { return nil }
func (rememberStore) ListRequests(context.Context, store.ListRequestsInput) ([]domain.EgressRequest, error) {
	return nil, nil
}
func (rememberStore) ListRules(context.Context) ([]domain.PolicyRule, error) { return nil, nil }
func (rememberStore) ListAuditEvents(context.Context) ([]domain.AuditEvent, error) { return nil, nil }
func (rememberStore) MatchRules(context.Context, store.MatchRulesInput) ([]domain.PolicyRule, error) {
	return nil, nil
}
func (rememberStore) CreateEgressRequest(context.Context, store.CreateEgressRequestInput) (domain.EgressRequest, error) {
	return domain.EgressRequest{}, nil
}
func (rememberStore) InsertAuditEvent(context.Context, string, string, string, map[string]any) error {
	return nil
}
func (s rememberStore) GetEgressRequest(context.Context, string) (domain.EgressRequest, error) {
	return s.pending, nil
}
func (rememberStore) ApproveRequestOnce(context.Context, string, string, store.AuditInput) (domain.EgressRequest, error) {
	return domain.EgressRequest{}, nil
}
func (rememberStore) ApproveRequestWithOrgRule(context.Context, string, string, store.AuditInput) (domain.EgressRequest, domain.PolicyRule, error) {
	return domain.EgressRequest{}, domain.PolicyRule{}, nil
}
func (rememberStore) DeletePolicyRule(context.Context, string, store.AuditInput) error { return nil }
func (rememberStore) DenyRequest(context.Context, string, string, string, store.AuditInput) (domain.EgressRequest, error) {
	return domain.EgressRequest{}, nil
}
func (rememberStore) FindConsumableApproval(context.Context, store.ApprovalMatchInput) (*domain.EgressRequest, error) {
	return nil, nil
}
func (rememberStore) HasDeniedPattern(context.Context, store.ApprovalMatchInput) (bool, error) {
	return false, nil
}
func (rememberStore) MarkApprovalConsumed(context.Context, string) error { return nil }

func TestApproveRememberRejectsCONNECT(t *testing.T) {
	svc := service.NewEgress(rememberStore{
		pending: domain.EgressRequest{ID: "req-connect", Method: "CONNECT", Host: "api.github.com"},
	}, policy.NewRuleEngine(rememberStore{}))

	_, err := svc.Approve(context.Background(), "req-connect", "admin-1", domain.ApproveRequestBody{
		Remember: true,
		Scope:    domain.RuleScopeOrg,
	})
	if err == nil {
		t.Fatal("expected error for remember=true on CONNECT")
	}
	var blocked domain.ErrRememberCONNECTNotAllowed
	if !errors.As(err, &blocked) {
		t.Fatalf("error = %v, want ErrRememberCONNECTNotAllowed", err)
	}
}

func TestApproveRememberRejectsNonOrgScope(t *testing.T) {
	svc := service.NewEgress(&approvalStore{}, policy.NewRuleEngine(&approvalStore{}))

	_, err := svc.Approve(context.Background(), "req-3", "admin-1", domain.ApproveRequestBody{
		Remember: true,
		Scope:    domain.RuleScopeAgent,
	})
	if err == nil {
		t.Fatal("expected error for remember=true with scope=agent")
	}
	var unsupported domain.ErrRememberScopeNotSupported
	if !errors.As(err, &unsupported) {
		t.Fatalf("error = %v, want ErrRememberScopeNotSupported", err)
	}
}

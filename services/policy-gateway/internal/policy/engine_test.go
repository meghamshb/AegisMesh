package policy_test

import (
	"context"
	"testing"

	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/policy"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/store"
)

type stubStore struct {
	rules              []domain.PolicyRule
	consumableApproval *domain.EgressRequest
	deniedPattern      bool
}

func (s stubStore) Ping(context.Context) error { return nil }
func (s stubStore) ListRequests(context.Context, store.ListRequestsInput) ([]domain.EgressRequest, error) {
	return nil, nil
}
func (s stubStore) ListRules(context.Context) ([]domain.PolicyRule, error) { return s.rules, nil }
func (s stubStore) ListAuditEvents(context.Context) ([]domain.AuditEvent, error) { return nil, nil }
func (s stubStore) MatchRules(_ context.Context, _ store.MatchRulesInput) ([]domain.PolicyRule, error) {
	return s.rules, nil
}
func (s stubStore) CreateEgressRequest(context.Context, store.CreateEgressRequestInput) (domain.EgressRequest, error) {
	return domain.EgressRequest{}, nil
}
func (s stubStore) InsertAuditEvent(context.Context, string, string, string, map[string]any) error {
	return nil
}
func (s stubStore) GetEgressRequest(context.Context, string) (domain.EgressRequest, error) {
	return domain.EgressRequest{}, nil
}
func (s stubStore) ApproveRequestOnce(context.Context, string, string) (domain.EgressRequest, error) {
	return domain.EgressRequest{}, nil
}
func (s stubStore) DenyRequest(context.Context, string, string, string) (domain.EgressRequest, error) {
	return domain.EgressRequest{}, nil
}
func (s stubStore) FindConsumableApproval(context.Context, store.ApprovalMatchInput) (*domain.EgressRequest, error) {
	return s.consumableApproval, nil
}
func (s stubStore) HasDeniedPattern(context.Context, store.ApprovalMatchInput) (bool, error) {
	return s.deniedPattern, nil
}
func (s stubStore) MarkApprovalConsumed(context.Context, string) error { return nil }

func TestEvaluatePendingWhenNoRules(t *testing.T) {
	engine := policy.NewRuleEngine(stubStore{})
	eval, err := engine.Evaluate(context.Background(), policy.Request{
		AgentID: "agent",
		OrgID:   "org",
		Method:  "GET",
		Host:    "example.com",
		Port:    443,
		Path:    "/",
		Scheme:  "https",
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if eval.Decision != policy.DecisionPending {
		t.Fatalf("decision = %q, want pending", eval.Decision)
	}
	if eval.RuleID != nil || eval.ApprovalGrantID != nil {
		t.Fatalf("expected no rule or approval grant, got rule=%v approval=%v", eval.RuleID, eval.ApprovalGrantID)
	}
}

func TestEvaluateDenyBeforeAllow(t *testing.T) {
	rules := []domain.PolicyRule{
		{ID: "allow-1", Effect: domain.RuleEffectAllow},
		{ID: "deny-1", Effect: domain.RuleEffectDeny},
	}
	engine := policy.NewRuleEngine(stubStore{rules: rules})
	eval, err := engine.Evaluate(context.Background(), policy.Request{
		AgentID: "agent",
		OrgID:   "org",
		Method:  "GET",
		Host:    "example.com",
		Port:    443,
		Path:    "/",
		Scheme:  "https",
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if eval.Decision != policy.DecisionDeny {
		t.Fatalf("decision = %q, want deny", eval.Decision)
	}
	if eval.RuleID == nil || *eval.RuleID != "deny-1" {
		t.Fatalf("ruleID = %v, want deny-1", eval.RuleID)
	}
}

func TestEvaluateConsumableApproval(t *testing.T) {
	approvalID := "approval-1"
	engine := policy.NewRuleEngine(stubStore{
		consumableApproval: &domain.EgressRequest{ID: approvalID},
	})
	eval, err := engine.Evaluate(context.Background(), policy.Request{
		AgentID: "agent",
		OrgID:   "org",
		Method:  "CONNECT",
		Host:    "api.github.com",
		Port:    443,
		Path:    "/",
		Scheme:  "https",
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if eval.Decision != policy.DecisionAllow {
		t.Fatalf("decision = %q, want allow", eval.Decision)
	}
	if eval.ApprovalGrantID == nil || *eval.ApprovalGrantID != approvalID {
		t.Fatalf("approvalGrantID = %v, want %s", eval.ApprovalGrantID, approvalID)
	}
}

func TestEvaluateDeniedPattern(t *testing.T) {
	engine := policy.NewRuleEngine(stubStore{deniedPattern: true})
	eval, err := engine.Evaluate(context.Background(), policy.Request{
		AgentID: "agent",
		OrgID:   "org",
		Method:  "CONNECT",
		Host:    "api.github.com",
		Port:    443,
		Path:    "/",
		Scheme:  "https",
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if eval.Decision != policy.DecisionDeny {
		t.Fatalf("decision = %q, want deny", eval.Decision)
	}
}

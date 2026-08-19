package policy_test

import (
	"context"
	"testing"

	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/policy"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/store"
)

type stubStore struct {
	rules []domain.PolicyRule
}

func (s stubStore) Ping(context.Context) error { return nil }
func (s stubStore) ListPendingRequests(context.Context) ([]domain.EgressRequest, error) {
	return nil, nil
}
func (s stubStore) ListRules(context.Context) ([]domain.PolicyRule, error) { return s.rules, nil }
func (s stubStore) MatchRules(_ context.Context, _ store.MatchRulesInput) ([]domain.PolicyRule, error) {
	return s.rules, nil
}
func (s stubStore) CreateEgressRequest(context.Context, store.CreateEgressRequestInput) (domain.EgressRequest, error) {
	return domain.EgressRequest{}, nil
}
func (s stubStore) InsertAuditEvent(context.Context, string, string, string, map[string]any) error {
	return nil
}

func TestEvaluatePendingWhenNoRules(t *testing.T) {
	engine := policy.NewRuleEngine(stubStore{})
	decision, ruleID, err := engine.Evaluate(context.Background(), policy.Request{
		OrgID:  "org",
		Method: "GET",
		Host:   "example.com",
		Port:   443,
		Path:   "/",
		Scheme: "https",
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if decision != policy.DecisionPending {
		t.Fatalf("decision = %q, want pending", decision)
	}
	if ruleID != nil {
		t.Fatalf("ruleID = %v, want nil", ruleID)
	}
}

func TestEvaluateDenyBeforeAllow(t *testing.T) {
	rules := []domain.PolicyRule{
		{ID: "allow-1", Effect: domain.RuleEffectAllow},
		{ID: "deny-1", Effect: domain.RuleEffectDeny},
	}
	engine := policy.NewRuleEngine(stubStore{rules: rules})
	decision, ruleID, err := engine.Evaluate(context.Background(), policy.Request{
		OrgID:  "org",
		Method: "GET",
		Host:   "example.com",
		Port:   443,
		Path:   "/",
		Scheme: "https",
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if decision != policy.DecisionDeny {
		t.Fatalf("decision = %q, want deny", decision)
	}
	if ruleID == nil || *ruleID != "deny-1" {
		t.Fatalf("ruleID = %v, want deny-1", ruleID)
	}
}

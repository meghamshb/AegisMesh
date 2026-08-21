package policy_test

import (
	"context"
	"testing"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/policy"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store/storetest"
)

// stubStore overrides only the four methods the rule engine actually calls;
// storetest.Stub supplies the rest of store.Store.
type stubStore struct {
	storetest.Stub
	rules              []domain.PolicyRule
	consumableApproval *domain.EgressRequest
	deniedPattern      bool

	// lastMatch/lastApprovalMatch record what the engine asked for, so tests
	// can assert the caller's org is actually propagated into the query.
	lastMatch         *store.MatchRulesInput
	lastApprovalMatch *store.ApprovalMatchInput
}

func (s *stubStore) ListRules(context.Context, store.ListRulesInput) ([]domain.PolicyRule, error) {
	return s.rules, nil
}

func (s *stubStore) MatchRules(_ context.Context, in store.MatchRulesInput) ([]domain.PolicyRule, error) {
	s.lastMatch = &in
	return s.rules, nil
}

func (s *stubStore) FindConsumableApproval(_ context.Context, in store.ApprovalMatchInput) (*domain.EgressRequest, error) {
	s.lastApprovalMatch = &in
	return s.consumableApproval, nil
}

func (s *stubStore) HasDeniedPattern(_ context.Context, in store.ApprovalMatchInput) (bool, error) {
	s.lastApprovalMatch = &in
	return s.deniedPattern, nil
}

func TestEvaluatePendingWhenNoRules(t *testing.T) {
	engine := policy.NewRuleEngine(&stubStore{})
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
	engine := policy.NewRuleEngine(&stubStore{rules: rules})
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
	engine := policy.NewRuleEngine(&stubStore{
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

func TestEvaluateOrgAllowRule(t *testing.T) {
	ruleID := "org-allow-1"
	engine := policy.NewRuleEngine(&stubStore{
		rules: []domain.PolicyRule{
			{ID: ruleID, Effect: domain.RuleEffectAllow, Scope: domain.RuleScopeOrg},
		},
	})
	eval, err := engine.Evaluate(context.Background(), policy.Request{
		AgentID: "agent",
		UserID:  "user",
		OrgID:   "org",
		Method:  "GET",
		Host:    "api.github.com",
		Port:    443,
		Path:    "/repos/acme/widget",
		Scheme:  "https",
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if eval.Decision != policy.DecisionAllow {
		t.Fatalf("decision = %q, want allow", eval.Decision)
	}
	if eval.RuleID == nil || *eval.RuleID != ruleID {
		t.Fatalf("ruleID = %v, want %s", eval.RuleID, ruleID)
	}
	if eval.ApprovalGrantID != nil {
		t.Fatalf("expected no consumable approval grant, got %v", eval.ApprovalGrantID)
	}
}

func TestEvaluateAgentDenyBeforeOrgAllow(t *testing.T) {
	ruleID := "org-allow-1"
	engine := policy.NewRuleEngine(&stubStore{
		rules: []domain.PolicyRule{
			{ID: ruleID, Effect: domain.RuleEffectAllow, Scope: domain.RuleScopeOrg},
		},
		deniedPattern: true,
	})
	eval, err := engine.Evaluate(context.Background(), policy.Request{
		AgentID: "agent",
		UserID:  "user",
		OrgID:   "org",
		Method:  "GET",
		Host:    "api.github.com",
		Port:    443,
		Path:    "/repos/acme/widget",
		Scheme:  "https",
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if eval.Decision != policy.DecisionDeny {
		t.Fatalf("decision = %q, want deny", eval.Decision)
	}
	if eval.RuleID != nil {
		t.Fatalf("ruleID = %v, want nil when agent deny pattern wins", eval.RuleID)
	}
}

func TestEvaluateDeniedPattern(t *testing.T) {
	engine := policy.NewRuleEngine(&stubStore{deniedPattern: true})
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

// --- Phase 5.5: scoped rule precedence matrix ---
// Locked precedence (documented in docs/specs/hermes-policy-gateway.md):
//  1. any matching deny wins, regardless of scope specificity
//  2. otherwise, the most specific matching allow wins: agent > user > org

func evalRequest() policy.Request {
	return policy.Request{
		AgentID: "agent-1",
		UserID:  "user-1",
		OrgID:   "org-1",
		Method:  "GET",
		Host:    "api.github.com",
		Port:    443,
		Path:    "/repos/acme/widget",
		Scheme:  "https",
	}
}

func TestPrecedenceMatrix(t *testing.T) {
	tests := []struct {
		name       string
		rules      []domain.PolicyRule
		wantDeny   bool
		wantRuleID string // only checked when non-empty and decision is allow
	}{
		{
			name:       "org allow only",
			rules:      []domain.PolicyRule{{ID: "org-allow", Scope: domain.RuleScopeOrg, Effect: domain.RuleEffectAllow}},
			wantRuleID: "org-allow",
		},
		{
			name:       "user allow only",
			rules:      []domain.PolicyRule{{ID: "user-allow", Scope: domain.RuleScopeUser, Effect: domain.RuleEffectAllow}},
			wantRuleID: "user-allow",
		},
		{
			name:       "agent allow only",
			rules:      []domain.PolicyRule{{ID: "agent-allow", Scope: domain.RuleScopeAgent, Effect: domain.RuleEffectAllow}},
			wantRuleID: "agent-allow",
		},
		{
			name: "org allow + agent deny: deny wins",
			rules: []domain.PolicyRule{
				{ID: "org-allow", Scope: domain.RuleScopeOrg, Effect: domain.RuleEffectAllow},
				{ID: "agent-deny", Scope: domain.RuleScopeAgent, Effect: domain.RuleEffectDeny},
			},
			wantDeny: true,
		},
		{
			name: "org deny + agent allow: deny still wins",
			rules: []domain.PolicyRule{
				{ID: "org-deny", Scope: domain.RuleScopeOrg, Effect: domain.RuleEffectDeny},
				{ID: "agent-allow", Scope: domain.RuleScopeAgent, Effect: domain.RuleEffectAllow},
			},
			wantDeny: true,
		},
		{
			name: "org allow + user allow + agent allow: most specific (agent) wins",
			rules: []domain.PolicyRule{
				{ID: "org-allow", Scope: domain.RuleScopeOrg, Effect: domain.RuleEffectAllow},
				{ID: "user-allow", Scope: domain.RuleScopeUser, Effect: domain.RuleEffectAllow},
				{ID: "agent-allow", Scope: domain.RuleScopeAgent, Effect: domain.RuleEffectAllow},
			},
			wantRuleID: "agent-allow",
		},
		{
			name: "org allow + user allow (no agent rule): user wins",
			rules: []domain.PolicyRule{
				{ID: "org-allow", Scope: domain.RuleScopeOrg, Effect: domain.RuleEffectAllow},
				{ID: "user-allow", Scope: domain.RuleScopeUser, Effect: domain.RuleEffectAllow},
			},
			wantRuleID: "user-allow",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine := policy.NewRuleEngine(&stubStore{rules: tc.rules})
			eval, err := engine.Evaluate(context.Background(), evalRequest())
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if tc.wantDeny {
				if eval.Decision != policy.DecisionDeny {
					t.Fatalf("decision = %q, want deny", eval.Decision)
				}
				return
			}
			if eval.Decision != policy.DecisionAllow {
				t.Fatalf("decision = %q, want allow", eval.Decision)
			}
			if tc.wantRuleID != "" {
				if eval.RuleID == nil || *eval.RuleID != tc.wantRuleID {
					t.Fatalf("ruleID = %v, want %s", eval.RuleID, tc.wantRuleID)
				}
			}
		})
	}
}

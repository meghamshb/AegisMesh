package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/policy"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/service"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
)

type createRuleStore struct {
	approvalStore
	created store.CreatePolicyRuleInput
}

func (s *createRuleStore) CreatePolicyRule(_ context.Context, in store.CreatePolicyRuleInput, audit store.AuditInput) (domain.PolicyRule, error) {
	s.created = in
	s.auditEvents = append(s.auditEvents, audit.EventType)
	return domain.PolicyRule{ID: "rule-new", Host: in.Host, PathPrefix: in.PathPrefix}, nil
}

func TestCreateRuleNormalizesDefaults(t *testing.T) {
	st := &createRuleStore{}
	svc := service.NewEgress(st, policy.NewRuleEngine(st))

	_, err := svc.CreateRule(context.Background(), "11111111-1111-1111-1111-111111111010", "admin-1", domain.CreatePolicyRuleBody{
		Scope:      domain.RuleScopeOrg,
		ScopeRefID: "11111111-1111-1111-1111-111111111010",
		Effect:     domain.RuleEffectAllow,
		Host:       "API.GITHUB.COM",
		Method:     "",
	})
	if err != nil {
		t.Fatalf("CreateRule() error = %v", err)
	}
	if st.created.Host != "api.github.com" {
		t.Fatalf("host = %q, want api.github.com", st.created.Host)
	}
	if st.created.Method != "*" {
		t.Fatalf("method = %q, want *", st.created.Method)
	}
	if st.created.Port != 443 {
		t.Fatalf("port = %d, want 443", st.created.Port)
	}
	if len(st.auditEvents) != 1 || st.auditEvents[0] != "policy_rule_created" {
		t.Fatalf("audit events = %v", st.auditEvents)
	}
}

func TestCreateRuleRejectsCONNECT(t *testing.T) {
	svc := service.NewEgress(&approvalStore{}, policy.NewRuleEngine(&approvalStore{}))

	_, err := svc.CreateRule(context.Background(), "11111111-1111-1111-1111-111111111010", "admin-1", domain.CreatePolicyRuleBody{
		Scope:      domain.RuleScopeOrg,
		ScopeRefID: "11111111-1111-1111-1111-111111111010",
		Effect:     domain.RuleEffectAllow,
		Host:       "example.org",
		Method:     "CONNECT",
	})
	if err == nil {
		t.Fatal("expected CONNECT rule rejection")
	}
	var blocked domain.ErrRuleCONNECTNotAllowed
	if !errors.As(err, &blocked) {
		t.Fatalf("error = %v, want ErrRuleCONNECTNotAllowed", err)
	}
}

func TestApproveRememberRejectsPastExpiresAt(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	svc := service.NewEgress(rememberStore{
		pending: domain.EgressRequest{ID: "req-expired", Method: "GET", Host: "api.github.com"},
	}, policy.NewRuleEngine(rememberStore{}))

	_, err := svc.Approve(context.Background(), "req-expired", "admin-1", domain.ApproveRequestBody{
		Remember:  true,
		Scope:     domain.RuleScopeOrg,
		ExpiresAt: &past,
	})
	if err == nil {
		t.Fatal("expected expires_at validation error")
	}
	var expiresPast domain.ErrExpiresAtInPast
	if !errors.As(err, &expiresPast) {
		t.Fatalf("error = %v, want ErrExpiresAtInPast", err)
	}
}

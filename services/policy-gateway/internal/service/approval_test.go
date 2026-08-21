package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/policy"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/service"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store/storetest"
)

type approvalStore struct {
	storetest.Stub
	pending         domain.EgressRequest
	approvedOnce    domain.EgressRequest
	approvedWithOrg domain.EgressRequest
	orgRule         domain.PolicyRule
	auditEvents     []string
	usersByID       map[string]domain.User
	agentsByID      map[string]domain.Agent
	lastScope       domain.RuleScope
	lastScopeRefID  string

	// Recorded org arguments, so tests can assert the caller's org is threaded
	// all the way into the store rather than silently dropped.
	lastGetOrgID     string
	lastApproveOrgID string
	lastDenyOrgID    string
	lastDeleteOrgID  string
}

func (s *approvalStore) InsertAuditEvent(_ context.Context, _, _, eventType, _ string, _ map[string]any) error {
	s.auditEvents = append(s.auditEvents, eventType)
	return nil
}

func (s *approvalStore) GetEgressRequest(_ context.Context, orgID, _ string) (domain.EgressRequest, error) {
	s.lastGetOrgID = orgID
	return s.pending, nil
}

func (s *approvalStore) ApproveRequestOnce(_ context.Context, orgID, _, _ string, audit store.AuditInput) (domain.EgressRequest, error) {
	s.auditEvents = append(s.auditEvents, audit.EventType)
	s.lastApproveOrgID = orgID
	return s.approvedOnce, nil
}

func (s *approvalStore) ApproveRequestWithScopedRule(_ context.Context, orgID, _, _ string, scope domain.RuleScope, scopeRefID string, _ store.OrgRuleOptions, audit store.AuditInput) (domain.EgressRequest, domain.PolicyRule, error) {
	s.auditEvents = append(s.auditEvents, audit.EventType)
	s.lastApproveOrgID = orgID
	s.lastScope = scope
	s.lastScopeRefID = scopeRefID
	return s.approvedWithOrg, s.orgRule, nil
}

func (s *approvalStore) GetUser(_ context.Context, orgID, id string) (domain.User, error) {
	if s.usersByID != nil {
		if u, ok := s.usersByID[id]; ok {
			if u.OrgID != "" && u.OrgID != orgID {
				return domain.User{}, domain.ErrNotFound{Resource: "user", ID: id}
			}
			return u, nil
		}
		return domain.User{}, domain.ErrNotFound{Resource: "user", ID: id}
	}
	return domain.User{}, nil
}

func (s *approvalStore) GetAgent(_ context.Context, orgID, id string) (domain.Agent, error) {
	if s.agentsByID != nil {
		if a, ok := s.agentsByID[id]; ok {
			if a.OrgID != "" && a.OrgID != orgID {
				return domain.Agent{}, domain.ErrNotFound{Resource: "agent", ID: id}
			}
			return a, nil
		}
		return domain.Agent{}, domain.ErrNotFound{Resource: "agent", ID: id}
	}
	return domain.Agent{}, nil
}

func (s *approvalStore) DeletePolicyRule(_ context.Context, orgID, _ string, _ store.AuditInput) error {
	s.lastDeleteOrgID = orgID
	return nil
}

func (s *approvalStore) DenyRequest(_ context.Context, orgID, _, _, _ string, _ store.AuditInput) (domain.EgressRequest, error) {
	s.lastDenyOrgID = orgID
	return domain.EgressRequest{}, nil
}

func TestApproveOnceUsesOnceAuditEvent(t *testing.T) {
	st := &approvalStore{
		approvedOnce: domain.EgressRequest{ID: "req-1", Host: "example.com", Port: 443, Method: "GET", Path: "/"},
	}
	svc := service.NewEgress(st, policy.NewRuleEngine(st))

	approved, err := svc.Approve(context.Background(), "org-1", "req-1", "admin-1", domain.ApproveRequestBody{})
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

	approved, err := svc.Approve(context.Background(), "org-1", "req-2", "admin-1", domain.ApproveRequestBody{
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

func (s rememberAuditStore) GetEgressRequest(context.Context, string, string) (domain.EgressRequest, error) {
	return s.pending, nil
}

// rememberStore only needs to hand back a fixed pending request; the embedded
// stub covers the rest of store.Store.
type rememberStore struct {
	storetest.Stub
	pending domain.EgressRequest
}

func (s rememberStore) GetEgressRequest(context.Context, string, string) (domain.EgressRequest, error) {
	return s.pending, nil
}

func TestApproveRememberRejectsCONNECT(t *testing.T) {
	svc := service.NewEgress(rememberStore{
		pending: domain.EgressRequest{ID: "req-connect", Method: "CONNECT", Host: "api.github.com"},
	}, policy.NewRuleEngine(rememberStore{}))

	_, err := svc.Approve(context.Background(), "org-1", "req-connect", "admin-1", domain.ApproveRequestBody{
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

func TestApproveRememberRejectsUnknownScope(t *testing.T) {
	svc := service.NewEgress(&approvalStore{}, policy.NewRuleEngine(&approvalStore{}))

	_, err := svc.Approve(context.Background(), "org-1", "req-3", "admin-1", domain.ApproveRequestBody{
		Remember: true,
		Scope:    domain.RuleScope("bogus"),
	})
	if err == nil {
		t.Fatal("expected error for remember=true with an unsupported scope")
	}
	var unsupported domain.ErrRememberScopeNotSupported
	if !errors.As(err, &unsupported) {
		t.Fatalf("error = %v, want ErrRememberScopeNotSupported", err)
	}
}

func TestApproveRememberAgentScopeDerivesRefFromPendingRequest(t *testing.T) {
	st := &approvalStore{
		approvedWithOrg: domain.EgressRequest{ID: "req-agent", Host: "api.github.com", Port: 443, Method: "GET", Path: "/zen"},
	}
	svc := service.NewEgress(rememberAuditStore{approvalStore: st, pending: domain.EgressRequest{
		ID: "req-agent", Method: "GET", Host: "api.github.com", AgentID: "agent-42", UserID: "user-7", OrgID: "org-1",
	}}, policy.NewRuleEngine(st))

	approved, err := svc.Approve(context.Background(), "org-1", "req-agent", "admin-1", domain.ApproveRequestBody{
		Remember: true,
		Scope:    domain.RuleScopeAgent,
	})
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if approved.ID != "req-agent" {
		t.Fatalf("approved ID = %q, want req-agent", approved.ID)
	}
	if st.lastScope != domain.RuleScopeAgent || st.lastScopeRefID != "agent-42" {
		t.Fatalf("scope/scopeRefID = %q/%q, want agent/agent-42 (derived from pending request, not client input)", st.lastScope, st.lastScopeRefID)
	}
	if len(st.auditEvents) != 1 || st.auditEvents[0] != "egress_approved_agent_rule" {
		t.Fatalf("audit events = %v, want [egress_approved_agent_rule]", st.auditEvents)
	}
}

func TestApproveRememberUserScopeDerivesRefFromPendingRequest(t *testing.T) {
	st := &approvalStore{
		approvedWithOrg: domain.EgressRequest{ID: "req-user", Host: "api.github.com", Port: 443, Method: "GET", Path: "/zen"},
	}
	svc := service.NewEgress(rememberAuditStore{approvalStore: st, pending: domain.EgressRequest{
		ID: "req-user", Method: "GET", Host: "api.github.com", AgentID: "agent-42", UserID: "user-7", OrgID: "org-1",
	}}, policy.NewRuleEngine(st))

	_, err := svc.Approve(context.Background(), "org-1", "req-user", "admin-1", domain.ApproveRequestBody{
		Remember: true,
		Scope:    domain.RuleScopeUser,
	})
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if st.lastScope != domain.RuleScopeUser || st.lastScopeRefID != "user-7" {
		t.Fatalf("scope/scopeRefID = %q/%q, want user/user-7", st.lastScope, st.lastScopeRefID)
	}
	if len(st.auditEvents) != 1 || st.auditEvents[0] != "egress_approved_user_rule" {
		t.Fatalf("audit events = %v, want [egress_approved_user_rule]", st.auditEvents)
	}
}

func TestApproveRememberAgentScopeRejectsCONNECT(t *testing.T) {
	svc := service.NewEgress(rememberStore{
		pending: domain.EgressRequest{ID: "req-connect-agent", Method: "CONNECT", Host: "api.github.com", AgentID: "agent-42"},
	}, policy.NewRuleEngine(rememberStore{}))

	_, err := svc.Approve(context.Background(), "org-1", "req-connect-agent", "admin-1", domain.ApproveRequestBody{
		Remember: true,
		Scope:    domain.RuleScopeAgent,
	})
	if err == nil {
		t.Fatal("expected CONNECT remember rejection even at agent scope")
	}
	var blocked domain.ErrRememberCONNECTNotAllowed
	if !errors.As(err, &blocked) {
		t.Fatalf("error = %v, want ErrRememberCONNECTNotAllowed", err)
	}
}

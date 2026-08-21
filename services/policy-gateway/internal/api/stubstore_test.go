package api_test

import (
	"context"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store/storetest"
)

// stubStore is the API tests' in-memory store. It deliberately *enforces* the
// same tenancy contract the real Postgres store does: every org-scoped method
// filters on the orgID it is given, and a row that exists in another org is
// reported as ErrNotFound rather than returned. Without that, a handler could
// drop the caller's org entirely and every test here would still pass.
type stubStore struct {
	storetest.Stub
	organization domain.Organization
	users        []domain.User
	agents       []domain.Agent
	gateways     []domain.Gateway
	rules        []domain.PolicyRule
	requests     []domain.EgressRequest
	auditEvents  []domain.AuditEvent
}

func (stubStore) Ping(_ context.Context) error { return nil }

func (s stubStore) ListRequests(_ context.Context, in store.ListRequestsInput) ([]domain.EgressRequest, error) {
	out := make([]domain.EgressRequest, 0)
	for _, r := range s.requests {
		if r.OrgID != in.OrgID {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

func (s stubStore) GetEgressRequest(_ context.Context, orgID, id string) (domain.EgressRequest, error) {
	for _, r := range s.requests {
		if r.ID == id && r.OrgID == orgID {
			return r, nil
		}
	}
	return domain.EgressRequest{}, domain.ErrNotFound{Resource: "egress_request", ID: id}
}

func (s stubStore) ApproveRequestOnce(_ context.Context, orgID, id, _ string, _ store.AuditInput) (domain.EgressRequest, error) {
	for _, r := range s.requests {
		if r.ID == id && r.OrgID == orgID {
			r.Status = domain.RequestStatusApproved
			return r, nil
		}
	}
	return domain.EgressRequest{}, domain.ErrNotFound{Resource: "egress_request", ID: id}
}

func (s stubStore) ApproveRequestWithScopedRule(_ context.Context, orgID, id, _ string, _ domain.RuleScope, _ string, _ store.OrgRuleOptions, _ store.AuditInput) (domain.EgressRequest, domain.PolicyRule, error) {
	for _, r := range s.requests {
		if r.ID == id && r.OrgID == orgID {
			r.Status = domain.RequestStatusApproved
			return r, domain.PolicyRule{ID: "rule-from-remember", OrgID: orgID}, nil
		}
	}
	return domain.EgressRequest{}, domain.PolicyRule{}, domain.ErrNotFound{Resource: "egress_request", ID: id}
}

func (s stubStore) DenyRequest(_ context.Context, orgID, id, _, _ string, _ store.AuditInput) (domain.EgressRequest, error) {
	for _, r := range s.requests {
		if r.ID == id && r.OrgID == orgID {
			r.Status = domain.RequestStatusDenied
			return r, nil
		}
	}
	return domain.EgressRequest{}, domain.ErrNotFound{Resource: "egress_request", ID: id}
}

func (s stubStore) CreateEgressRequest(_ context.Context, in store.CreateEgressRequestInput) (domain.EgressRequest, error) {
	return domain.EgressRequest{ID: "test-id", OrgID: in.OrgID, Status: domain.RequestStatusPending}, nil
}

func (s stubStore) ListRules(_ context.Context, in store.ListRulesInput) ([]domain.PolicyRule, error) {
	out := make([]domain.PolicyRule, 0)
	for _, r := range s.rules {
		if r.OrgID != in.OrgID {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

func (s stubStore) DeletePolicyRule(_ context.Context, orgID, id string, _ store.AuditInput) error {
	for _, r := range s.rules {
		if r.ID == id && r.OrgID == orgID {
			return nil
		}
	}
	return domain.ErrNotFound{Resource: "policy_rule", ID: id}
}

func (s stubStore) CreatePolicyRule(_ context.Context, in store.CreatePolicyRuleInput, _ store.AuditInput) (domain.PolicyRule, error) {
	return domain.PolicyRule{ID: "new-rule-id", OrgID: in.OrgID, Scope: in.Scope, ScopeRefID: in.ScopeRefID, Effect: in.Effect, Host: in.Host}, nil
}

func (s stubStore) ListAuditEvents(_ context.Context, in store.ListAuditEventsInput) ([]domain.AuditEvent, error) {
	out := make([]domain.AuditEvent, 0)
	for _, e := range s.auditEvents {
		if e.OrgID != in.OrgID {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func (s stubStore) GetOrganization(_ context.Context, id string) (domain.Organization, error) {
	if s.organization.ID != id {
		return domain.Organization{}, domain.ErrNotFound{Resource: "organization", ID: id}
	}
	return s.organization, nil
}

func (s stubStore) ListUsers(_ context.Context, in store.ListUsersInput) ([]domain.User, error) {
	filtered := make([]domain.User, 0)
	for _, u := range s.users {
		if u.OrgID != in.OrgID {
			continue
		}
		if in.Status != "" && u.Status != in.Status {
			continue
		}
		filtered = append(filtered, u)
	}
	return filtered, nil
}

func (s stubStore) GetUser(_ context.Context, orgID, id string) (domain.User, error) {
	for _, u := range s.users {
		if u.ID == id && u.OrgID == orgID {
			return u, nil
		}
	}
	return domain.User{}, domain.ErrNotFound{Resource: "user", ID: id}
}

func (s stubStore) CreateUser(_ context.Context, in store.CreateUserInput) (domain.User, error) {
	return domain.User{ID: "new-user-id", OrgID: in.OrgID, DisplayName: in.DisplayName, Role: in.Role, Status: "active"}, nil
}

func (s stubStore) UpdateUser(_ context.Context, orgID, id string, in store.UpdateUserInput) (domain.User, error) {
	for _, u := range s.users {
		if u.ID != id || u.OrgID != orgID {
			continue
		}
		if in.DisplayName != nil {
			u.DisplayName = *in.DisplayName
		}
		if in.Role != nil {
			u.Role = *in.Role
		}
		if in.Status != nil {
			u.Status = *in.Status
		}
		return u, nil
	}
	return domain.User{}, domain.ErrNotFound{Resource: "user", ID: id}
}

func (s stubStore) ListAgents(_ context.Context, in store.ListAgentsInput) ([]domain.Agent, error) {
	filtered := make([]domain.Agent, 0)
	for _, a := range s.agents {
		if a.OrgID != in.OrgID {
			continue
		}
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

func (s stubStore) GetAgent(_ context.Context, orgID, id string) (domain.Agent, error) {
	for _, a := range s.agents {
		if a.ID == id && a.OrgID == orgID {
			return a, nil
		}
	}
	return domain.Agent{}, domain.ErrNotFound{Resource: "agent", ID: id}
}

func (s stubStore) ResolveAgentForAuth(_ context.Context, id string) (domain.Agent, error) {
	for _, a := range s.agents {
		if a.ID == id {
			return a, nil
		}
	}
	return domain.Agent{}, domain.ErrNotFound{Resource: "agent", ID: id}
}

func (s stubStore) UpdateAgent(_ context.Context, orgID, id string, in store.UpdateAgentInput) (domain.Agent, error) {
	for _, a := range s.agents {
		if a.ID != id || a.OrgID != orgID {
			continue
		}
		if in.Name != nil {
			a.Name = *in.Name
		}
		if in.Metadata != nil {
			a.Metadata = in.Metadata
		}
		return a, nil
	}
	return domain.Agent{}, domain.ErrNotFound{Resource: "agent", ID: id}
}

func (s stubStore) RegisterAgent(_ context.Context, in store.RegisterAgentInput, _ store.AuditInput) (domain.Agent, error) {
	// Mirrors the real store's in-transaction owner-org check.
	for _, u := range s.users {
		if u.ID == in.OwnerUserID {
			if u.OrgID != in.OrgID {
				return domain.Agent{}, domain.ErrNotFound{Resource: "user", ID: in.OwnerUserID}
			}
			return domain.Agent{ID: "new-agent-id", OrgID: in.OrgID, OwnerUserID: in.OwnerUserID, Name: in.Name, Status: "active"}, nil
		}
	}
	return domain.Agent{}, domain.ErrNotFound{Resource: "user", ID: in.OwnerUserID}
}

func (s stubStore) RevokeAgent(_ context.Context, orgID, agentID string, _ store.AuditInput) (domain.Agent, error) {
	for _, a := range s.agents {
		if a.ID == agentID && a.OrgID == orgID {
			a.Status = "revoked"
			return a, nil
		}
	}
	return domain.Agent{}, domain.ErrNotFound{Resource: "agent", ID: agentID}
}

func (s stubStore) CreateAgentCredential(_ context.Context, in store.CreateAgentCredentialInput, _ store.AuditInput) (domain.AgentCredential, error) {
	for _, a := range s.agents {
		if a.ID == in.AgentID && a.OrgID == in.OrgID {
			return domain.AgentCredential{ID: "cred-id", AgentID: in.AgentID, TokenPrefix: in.TokenPrefix, TokenHash: in.TokenHash, Status: "active"}, nil
		}
	}
	// Registration creates the agent and its credential in one call, so an
	// unknown-but-freshly-created agent id is expected here.
	if in.AgentID == "new-agent-id" {
		return domain.AgentCredential{ID: "cred-id", AgentID: in.AgentID, TokenPrefix: in.TokenPrefix, TokenHash: in.TokenHash, Status: "active"}, nil
	}
	return domain.AgentCredential{}, domain.ErrNotFound{Resource: "agent", ID: in.AgentID}
}

func (s stubStore) RotateAgentCredential(_ context.Context, orgID, agentID string, in store.CreateAgentCredentialInput, _ store.AuditInput) (domain.AgentCredential, error) {
	for _, a := range s.agents {
		if a.ID == agentID && a.OrgID == orgID {
			return domain.AgentCredential{ID: "cred-id-2", AgentID: agentID, TokenPrefix: in.TokenPrefix, TokenHash: in.TokenHash, Status: "active"}, nil
		}
	}
	return domain.AgentCredential{}, domain.ErrNotFound{Resource: "agent", ID: agentID}
}

func (s stubStore) GetAgentCredentialByHash(_ context.Context, _ string) (domain.AgentCredential, error) {
	return domain.AgentCredential{}, domain.ErrNotFound{Resource: "agent_credential", ID: "token"}
}

func (s stubStore) RegisterGateway(_ context.Context, in store.RegisterGatewayInput) (domain.Gateway, error) {
	return domain.Gateway{
		ID: "new-gateway-id", OrgID: in.OrgID, Name: in.Name, Status: "active",
		CredentialPrefix: in.CredentialPrefix, CredentialHash: in.CredentialHash,
	}, nil
}

func (s stubStore) ListGateways(_ context.Context, orgID string) ([]domain.Gateway, error) {
	filtered := make([]domain.Gateway, 0)
	for _, gw := range s.gateways {
		if gw.OrgID != orgID {
			continue
		}
		filtered = append(filtered, gw)
	}
	return filtered, nil
}

func (s stubStore) GetGateway(_ context.Context, orgID, id string) (domain.Gateway, error) {
	for _, gw := range s.gateways {
		if gw.ID == id && gw.OrgID == orgID {
			return gw, nil
		}
	}
	return domain.Gateway{}, domain.ErrNotFound{Resource: "gateway", ID: id}
}

func (s stubStore) GetGatewayByCredentialHash(_ context.Context, hash string) (domain.Gateway, error) {
	for _, gw := range s.gateways {
		if gw.CredentialHash == hash {
			return gw, nil
		}
	}
	return domain.Gateway{}, domain.ErrNotFound{Resource: "gateway", ID: "credential"}
}

func (s stubStore) UpdateGatewayHeartbeat(_ context.Context, orgID, id string, _ store.GatewayHeartbeatInput) (domain.Gateway, error) {
	for _, gw := range s.gateways {
		if gw.ID == id && gw.OrgID == orgID {
			return gw, nil
		}
	}
	return domain.Gateway{}, domain.ErrNotFound{Resource: "gateway", ID: id}
}

func (s stubStore) GetOrgPolicyVersion(_ context.Context, _ string) (int64, error) { return 3, nil }

func (s stubStore) ListRulesForOrgSnapshot(_ context.Context, orgID string) ([]domain.PolicyRule, error) {
	return []domain.PolicyRule{{ID: "snapshot-rule", OrgID: orgID, Scope: domain.RuleScopeOrg, Effect: domain.RuleEffectAllow}}, nil
}

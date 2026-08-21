// Package storetest provides a zero-value stub implementation of store.Store
// for use in tests.
//
// Before this existed, every test file hand-wrote a full store.Store fake, so
// adding one method to the interface meant editing six unrelated _test.go
// files - and, worse, a fake could silently drift from the real store's
// tenancy contract. Embed Stub instead and override only the methods a given
// test actually exercises:
//
//	type myFake struct {
//		storetest.Stub
//		users []domain.User
//	}
//
//	func (f *myFake) ListUsers(ctx context.Context, in store.ListUsersInput) ([]domain.User, error) {
//		// ... only what this test needs
//	}
//
// Methods defined on the outer type win over the promoted ones, so the stub
// only ever fills in the gaps.
package storetest

import (
	"context"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
)

// Stub implements store.Store; every method returns zero values and no error.
type Stub struct{}

// Compile-time proof that the stub stays in step with the interface. If
// store.Store gains a method, this fails here - once - instead of in every
// test file that embeds Stub.
var _ store.Store = Stub{}

func (Stub) Ping(context.Context) error { return nil }

func (Stub) ListRequests(context.Context, store.ListRequestsInput) ([]domain.EgressRequest, error) {
	return nil, nil
}

func (Stub) GetEgressRequest(context.Context, string, string) (domain.EgressRequest, error) {
	return domain.EgressRequest{}, nil
}

func (Stub) CreateEgressRequest(context.Context, store.CreateEgressRequestInput) (domain.EgressRequest, error) {
	return domain.EgressRequest{}, nil
}

func (Stub) ApproveRequestOnce(context.Context, string, string, string, store.AuditInput) (domain.EgressRequest, error) {
	return domain.EgressRequest{}, nil
}

func (Stub) ApproveRequestWithScopedRule(context.Context, string, string, string, domain.RuleScope, string, store.OrgRuleOptions, store.AuditInput) (domain.EgressRequest, domain.PolicyRule, error) {
	return domain.EgressRequest{}, domain.PolicyRule{}, nil
}

func (Stub) DenyRequest(context.Context, string, string, string, string, store.AuditInput) (domain.EgressRequest, error) {
	return domain.EgressRequest{}, nil
}

func (Stub) FindConsumableApproval(context.Context, store.ApprovalMatchInput) (*domain.EgressRequest, error) {
	return nil, nil
}

func (Stub) HasDeniedPattern(context.Context, store.ApprovalMatchInput) (bool, error) {
	return false, nil
}

func (Stub) MarkApprovalConsumed(context.Context, string, string) error { return nil }

func (Stub) ListRules(context.Context, store.ListRulesInput) ([]domain.PolicyRule, error) {
	return nil, nil
}

func (Stub) MatchRules(context.Context, store.MatchRulesInput) ([]domain.PolicyRule, error) {
	return nil, nil
}

func (Stub) CreatePolicyRule(context.Context, store.CreatePolicyRuleInput, store.AuditInput) (domain.PolicyRule, error) {
	return domain.PolicyRule{}, nil
}

func (Stub) DeletePolicyRule(context.Context, string, string, store.AuditInput) error { return nil }

func (Stub) GetOrgPolicyVersion(context.Context, string) (int64, error) { return 0, nil }

func (Stub) ListRulesForOrgSnapshot(context.Context, string) ([]domain.PolicyRule, error) {
	return nil, nil
}

func (Stub) ListAuditEvents(context.Context, store.ListAuditEventsInput) ([]domain.AuditEvent, error) {
	return nil, nil
}

func (Stub) InsertAuditEvent(context.Context, string, string, string, string, map[string]any) error {
	return nil
}

func (Stub) GetOrganization(context.Context, string) (domain.Organization, error) {
	return domain.Organization{}, nil
}

func (Stub) ListUsers(context.Context, store.ListUsersInput) ([]domain.User, error) {
	return nil, nil
}

func (Stub) GetUser(context.Context, string, string) (domain.User, error) {
	return domain.User{}, nil
}

func (Stub) CreateUser(context.Context, store.CreateUserInput) (domain.User, error) {
	return domain.User{}, nil
}

func (Stub) UpdateUser(context.Context, string, string, store.UpdateUserInput) (domain.User, error) {
	return domain.User{}, nil
}

func (Stub) ListAgents(context.Context, store.ListAgentsInput) ([]domain.Agent, error) {
	return nil, nil
}

func (Stub) GetAgent(context.Context, string, string) (domain.Agent, error) {
	return domain.Agent{}, nil
}

func (Stub) ResolveAgentForAuth(context.Context, string) (domain.Agent, error) {
	return domain.Agent{}, nil
}

func (Stub) UpdateAgent(context.Context, string, string, store.UpdateAgentInput) (domain.Agent, error) {
	return domain.Agent{}, nil
}

func (Stub) RegisterAgent(context.Context, store.RegisterAgentInput, store.AuditInput) (domain.Agent, error) {
	return domain.Agent{}, nil
}

func (Stub) RevokeAgent(context.Context, string, string, store.AuditInput) (domain.Agent, error) {
	return domain.Agent{}, nil
}

func (Stub) CreateAgentCredential(context.Context, store.CreateAgentCredentialInput, store.AuditInput) (domain.AgentCredential, error) {
	return domain.AgentCredential{}, nil
}

func (Stub) RotateAgentCredential(context.Context, string, string, store.CreateAgentCredentialInput, store.AuditInput) (domain.AgentCredential, error) {
	return domain.AgentCredential{}, nil
}

func (Stub) GetAgentCredentialByHash(context.Context, string) (domain.AgentCredential, error) {
	return domain.AgentCredential{}, nil
}

func (Stub) TouchAgentCredentialLastUsed(context.Context, string) error { return nil }

func (Stub) TouchAgentLastSeen(context.Context, string) error { return nil }

func (Stub) RegisterGateway(context.Context, store.RegisterGatewayInput) (domain.Gateway, error) {
	return domain.Gateway{}, nil
}

func (Stub) ListGateways(context.Context, string) ([]domain.Gateway, error) { return nil, nil }

func (Stub) GetGateway(context.Context, string, string) (domain.Gateway, error) {
	return domain.Gateway{}, nil
}

func (Stub) GetGatewayByCredentialHash(context.Context, string) (domain.Gateway, error) {
	return domain.Gateway{}, nil
}

func (Stub) UpdateGatewayHeartbeat(context.Context, string, string, store.GatewayHeartbeatInput) (domain.Gateway, error) {
	return domain.Gateway{}, nil
}

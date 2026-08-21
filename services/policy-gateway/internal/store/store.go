package store

import (
	"context"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
)

// Tenancy contract for this package
//
// Every tenant-owned row lives in exactly one organization. Each method below
// that reads or mutates such a row therefore takes the caller's org - either as
// an explicit orgID argument or as an OrgID field on its input struct - and the
// SQL filters on it. Callers must source that org from the *authenticated
// caller* (Principal.OrgID, AuthenticatedGateway.OrgID, or the authenticated
// agent's identity), never from a request body or query parameter.
//
// A lookup whose id exists but belongs to another org returns
// domain.ErrNotFound, exactly as a genuinely absent id does. That is
// deliberate: a distinct "forbidden" response would confirm the row exists and
// turn these endpoints into a cross-tenant existence oracle.
//
// The only methods without an org argument are ones where an org predicate
// would be meaningless or actively wrong:
//   - GetOrganization: the id *is* the org.
//   - GetAgentCredentialByHash / GetGatewayByCredentialHash: the secret hash is
//     the authenticator, and these run *before* any caller org is known.
//   - ResolveAgentForAuth: the credential-to-agent hop *inside* authentication,
//     which is what produces the org in the first place.
//   - GetUserByExternalSubject / GetUserByEmail: the same hop for human
//     callers (Phase 5.13) - an OIDC subject resolves to an actor, and that
//     actor is what determines the caller's org.
//   - TouchAgentLastSeen / TouchAgentCredentialLastUsed: post-authentication
//     bookkeeping on the caller's own already-verified row.

type CreateEgressRequestInput struct {
	AgentID string
	UserID  string
	OrgID   string
	Method  string
	Host    string
	Port    int
	Path    string
	Scheme  string
	Status  domain.RequestStatus
	RuleID  *string
}

type MatchRulesInput struct {
	OrgID   string
	UserID  string
	AgentID string
	Host    string
	Port    int
	Method  string
	Path    string
}

type ApprovalMatchInput struct {
	OrgID   string
	AgentID string
	Host    string
	Port    int
	Method  string
	Path    string
}

type ListRequestsInput struct {
	OrgID   string
	Status  *domain.RequestStatus
	Host    string
	UserID  string
	AgentID string
	From    *time.Time
	To      *time.Time
	Limit   int
	Offset  int
}

type AuditInput struct {
	OrgID           string
	EgressRequestID string
	EventType       string
	ActorID         string
	Metadata        map[string]any
}

type CreatePolicyRuleInput struct {
	OrgID      string
	Scope      domain.RuleScope
	ScopeRefID string
	Effect     domain.RuleEffect
	Host       string
	Port       int
	Method     string
	PathPrefix string
	ExpiresAt  *time.Time
	CreatedBy  string
}

type OrgRuleOptions struct {
	ExpiresAt *time.Time
}

type ListUsersInput struct {
	OrgID  string
	Status string
	Limit  int
	Offset int
}

type ListAgentsInput struct {
	OrgID  string
	UserID string
	Status string
	Limit  int
	Offset int
}

type ListRulesInput struct {
	OrgID      string
	Scope      string
	ScopeRefID string
	Effect     string
	Host       string
	Active     *bool
	Limit      int
	Offset     int
}

type ListAuditEventsInput struct {
	OrgID     string
	EventType string
	ActorID   string
	From      *time.Time
	To        *time.Time
	Limit     int
	Offset    int
}

type CreateUserInput struct {
	OrgID       string
	DisplayName string
	Email       *string
	Role        string
}

type UpdateUserInput struct {
	DisplayName *string
	Email       *string
	Role        *string
	Status      *string
}

type UpdateAgentInput struct {
	Name        *string
	ContainerID *string
	Metadata    map[string]any
}

type RegisterAgentInput struct {
	OrgID       string
	OwnerUserID string
	Name        string
	ContainerID *string
	Metadata    map[string]any
}

type CreateAgentCredentialInput struct {
	OrgID       string
	AgentID     string
	TokenPrefix string
	TokenHash   string
	CreatedBy   string
}

type RegisterGatewayInput struct {
	OrgID            string
	Name             string
	CredentialPrefix string
	CredentialHash   string
	Metadata         map[string]any
}

type GatewayHeartbeatInput struct {
	Version       string
	PolicyVersion int64
	ActiveAgents  int
	Metadata      map[string]any
}

type Store interface {
	Ping(ctx context.Context) error

	// Egress requests
	ListRequests(ctx context.Context, in ListRequestsInput) ([]domain.EgressRequest, error)
	GetEgressRequest(ctx context.Context, orgID, id string) (domain.EgressRequest, error)
	CreateEgressRequest(ctx context.Context, in CreateEgressRequestInput) (domain.EgressRequest, error)
	ApproveRequestOnce(ctx context.Context, orgID, id, decidedBy string, audit AuditInput) (domain.EgressRequest, error)
	ApproveRequestWithScopedRule(ctx context.Context, orgID, id, decidedBy string, scope domain.RuleScope, scopeRefID string, opts OrgRuleOptions, audit AuditInput) (domain.EgressRequest, domain.PolicyRule, error)
	DenyRequest(ctx context.Context, orgID, id, decidedBy, feedback string, audit AuditInput) (domain.EgressRequest, error)
	FindConsumableApproval(ctx context.Context, in ApprovalMatchInput) (*domain.EgressRequest, error)
	HasDeniedPattern(ctx context.Context, in ApprovalMatchInput) (bool, error)
	MarkApprovalConsumed(ctx context.Context, orgID, id string) error

	// Policy rules
	ListRules(ctx context.Context, in ListRulesInput) ([]domain.PolicyRule, error)
	MatchRules(ctx context.Context, in MatchRulesInput) ([]domain.PolicyRule, error)
	CreatePolicyRule(ctx context.Context, in CreatePolicyRuleInput, audit AuditInput) (domain.PolicyRule, error)
	DeletePolicyRule(ctx context.Context, orgID, id string, audit AuditInput) error
	GetOrgPolicyVersion(ctx context.Context, orgID string) (int64, error)
	ListRulesForOrgSnapshot(ctx context.Context, orgID string) ([]domain.PolicyRule, error)

	// Audit
	ListAuditEvents(ctx context.Context, in ListAuditEventsInput) ([]domain.AuditEvent, error)
	InsertAuditEvent(ctx context.Context, orgID, egressRequestID, eventType, actorID string, metadata map[string]any) error

	// Directory
	GetOrganization(ctx context.Context, id string) (domain.Organization, error)
	ListUsers(ctx context.Context, in ListUsersInput) ([]domain.User, error)
	GetUser(ctx context.Context, orgID, id string) (domain.User, error)
	GetUserByExternalSubject(ctx context.Context, externalSubject string) (domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (domain.User, error)
	LinkExternalSubject(ctx context.Context, orgID, userID, externalSubject string) error
	CreateUser(ctx context.Context, in CreateUserInput) (domain.User, error)
	UpdateUser(ctx context.Context, orgID, id string, in UpdateUserInput) (domain.User, error)
	ListAgents(ctx context.Context, in ListAgentsInput) ([]domain.Agent, error)
	GetAgent(ctx context.Context, orgID, id string) (domain.Agent, error)
	ResolveAgentForAuth(ctx context.Context, id string) (domain.Agent, error)
	UpdateAgent(ctx context.Context, orgID, id string, in UpdateAgentInput) (domain.Agent, error)
	RegisterAgent(ctx context.Context, in RegisterAgentInput, audit AuditInput) (domain.Agent, error)
	RevokeAgent(ctx context.Context, orgID, agentID string, audit AuditInput) (domain.Agent, error)

	// Agent credentials
	CreateAgentCredential(ctx context.Context, in CreateAgentCredentialInput, audit AuditInput) (domain.AgentCredential, error)
	RotateAgentCredential(ctx context.Context, orgID, agentID string, in CreateAgentCredentialInput, audit AuditInput) (domain.AgentCredential, error)
	GetAgentCredentialByHash(ctx context.Context, tokenHash string) (domain.AgentCredential, error)
	TouchAgentCredentialLastUsed(ctx context.Context, credentialID string) error
	TouchAgentLastSeen(ctx context.Context, agentID string) error

	// Gateways
	RegisterGateway(ctx context.Context, in RegisterGatewayInput) (domain.Gateway, error)
	ListGateways(ctx context.Context, orgID string) ([]domain.Gateway, error)
	GetGateway(ctx context.Context, orgID, id string) (domain.Gateway, error)
	GetGatewayByCredentialHash(ctx context.Context, credentialHash string) (domain.Gateway, error)
	UpdateGatewayHeartbeat(ctx context.Context, orgID, id string, in GatewayHeartbeatInput) (domain.Gateway, error)
}

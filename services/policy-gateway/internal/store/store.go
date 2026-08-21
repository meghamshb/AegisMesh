package store

import (
	"context"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
)

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
	AgentID string
	Host    string
	Port    int
	Method  string
	Path    string
}

type ListRequestsInput struct {
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
	Status string
	Limit  int
	Offset int
}

type ListAgentsInput struct {
	UserID string
	Status string
	Limit  int
	Offset int
}

type ListRulesInput struct {
	Scope      string
	ScopeRefID string
	Effect     string
	Host       string
	Active     *bool
	Limit      int
	Offset     int
}

type ListAuditEventsInput struct {
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
	Version  string
	Metadata map[string]any
}

type Store interface {
	Ping(ctx context.Context) error
	ListRequests(ctx context.Context, in ListRequestsInput) ([]domain.EgressRequest, error)
	ListRules(ctx context.Context, in ListRulesInput) ([]domain.PolicyRule, error)
	ListAuditEvents(ctx context.Context, in ListAuditEventsInput) ([]domain.AuditEvent, error)
	MatchRules(ctx context.Context, in MatchRulesInput) ([]domain.PolicyRule, error)
	CreateEgressRequest(ctx context.Context, in CreateEgressRequestInput) (domain.EgressRequest, error)
	InsertAuditEvent(ctx context.Context, egressRequestID, eventType, actorID string, metadata map[string]any) error
	GetEgressRequest(ctx context.Context, id string) (domain.EgressRequest, error)
	ApproveRequestOnce(ctx context.Context, id, decidedBy string, audit AuditInput) (domain.EgressRequest, error)
	ApproveRequestWithScopedRule(ctx context.Context, id, decidedBy string, scope domain.RuleScope, scopeRefID string, opts OrgRuleOptions, audit AuditInput) (domain.EgressRequest, domain.PolicyRule, error)
	CreatePolicyRule(ctx context.Context, in CreatePolicyRuleInput, audit AuditInput) (domain.PolicyRule, error)
	DeletePolicyRule(ctx context.Context, id string, audit AuditInput) error
	DenyRequest(ctx context.Context, id, decidedBy, feedback string, audit AuditInput) (domain.EgressRequest, error)
	FindConsumableApproval(ctx context.Context, in ApprovalMatchInput) (*domain.EgressRequest, error)
	HasDeniedPattern(ctx context.Context, in ApprovalMatchInput) (bool, error)
	MarkApprovalConsumed(ctx context.Context, id string) error
	GetOrganization(ctx context.Context, id string) (domain.Organization, error)
	ListUsers(ctx context.Context, in ListUsersInput) ([]domain.User, error)
	GetUser(ctx context.Context, id string) (domain.User, error)
	CreateUser(ctx context.Context, in CreateUserInput) (domain.User, error)
	UpdateUser(ctx context.Context, id string, in UpdateUserInput) (domain.User, error)
	ListAgents(ctx context.Context, in ListAgentsInput) ([]domain.Agent, error)
	GetAgent(ctx context.Context, id string) (domain.Agent, error)
	UpdateAgent(ctx context.Context, id string, in UpdateAgentInput) (domain.Agent, error)
	RegisterAgent(ctx context.Context, in RegisterAgentInput, audit AuditInput) (domain.Agent, error)
	RevokeAgent(ctx context.Context, agentID string, audit AuditInput) (domain.Agent, error)
	CreateAgentCredential(ctx context.Context, in CreateAgentCredentialInput, audit AuditInput) (domain.AgentCredential, error)
	RotateAgentCredential(ctx context.Context, agentID string, in CreateAgentCredentialInput, audit AuditInput) (domain.AgentCredential, error)
	GetAgentCredentialByHash(ctx context.Context, tokenHash string) (domain.AgentCredential, error)
	TouchAgentCredentialLastUsed(ctx context.Context, credentialID string) error
	TouchAgentLastSeen(ctx context.Context, agentID string) error
	RegisterGateway(ctx context.Context, in RegisterGatewayInput) (domain.Gateway, error)
	ListGateways(ctx context.Context, orgID string) ([]domain.Gateway, error)
	GetGateway(ctx context.Context, id string) (domain.Gateway, error)
	GetGatewayByCredentialHash(ctx context.Context, credentialHash string) (domain.Gateway, error)
	UpdateGatewayHeartbeat(ctx context.Context, id string, in GatewayHeartbeatInput) (domain.Gateway, error)
	GetOrgPolicyVersion(ctx context.Context, orgID string) (int64, error)
	ListRulesForOrgSnapshot(ctx context.Context, orgID string) ([]domain.PolicyRule, error)
}

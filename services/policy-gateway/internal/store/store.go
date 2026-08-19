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
	Status *domain.RequestStatus
	Host   string
	UserID string
	AgentID string
	Limit  int
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

type Store interface {
	Ping(ctx context.Context) error
	ListRequests(ctx context.Context, in ListRequestsInput) ([]domain.EgressRequest, error)
	ListRules(ctx context.Context) ([]domain.PolicyRule, error)
	ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error)
	MatchRules(ctx context.Context, in MatchRulesInput) ([]domain.PolicyRule, error)
	CreateEgressRequest(ctx context.Context, in CreateEgressRequestInput) (domain.EgressRequest, error)
	InsertAuditEvent(ctx context.Context, egressRequestID, eventType, actorID string, metadata map[string]any) error
	GetEgressRequest(ctx context.Context, id string) (domain.EgressRequest, error)
	ApproveRequestOnce(ctx context.Context, id, decidedBy string, audit AuditInput) (domain.EgressRequest, error)
	ApproveRequestWithOrgRule(ctx context.Context, id, decidedBy string, opts OrgRuleOptions, audit AuditInput) (domain.EgressRequest, domain.PolicyRule, error)
	CreatePolicyRule(ctx context.Context, in CreatePolicyRuleInput, audit AuditInput) (domain.PolicyRule, error)
	DeletePolicyRule(ctx context.Context, id string, audit AuditInput) error
	DenyRequest(ctx context.Context, id, decidedBy, feedback string, audit AuditInput) (domain.EgressRequest, error)
	FindConsumableApproval(ctx context.Context, in ApprovalMatchInput) (*domain.EgressRequest, error)
	HasDeniedPattern(ctx context.Context, in ApprovalMatchInput) (bool, error)
	MarkApprovalConsumed(ctx context.Context, id string) error
}

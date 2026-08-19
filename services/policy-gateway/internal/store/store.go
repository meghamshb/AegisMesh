package store

import (
	"context"

	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/domain"
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
	OrgID  string
	Host   string
	Port   int
	Method string
	Path   string
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

type Store interface {
	Ping(ctx context.Context) error
	ListRequests(ctx context.Context, in ListRequestsInput) ([]domain.EgressRequest, error)
	ListRules(ctx context.Context) ([]domain.PolicyRule, error)
	ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error)
	MatchRules(ctx context.Context, in MatchRulesInput) ([]domain.PolicyRule, error)
	CreateEgressRequest(ctx context.Context, in CreateEgressRequestInput) (domain.EgressRequest, error)
	InsertAuditEvent(ctx context.Context, egressRequestID, eventType, actorID string, metadata map[string]any) error
	GetEgressRequest(ctx context.Context, id string) (domain.EgressRequest, error)
	ApproveRequestOnce(ctx context.Context, id, decidedBy string) (domain.EgressRequest, error)
	DenyRequest(ctx context.Context, id, decidedBy, feedback string) (domain.EgressRequest, error)
	FindConsumableApproval(ctx context.Context, in ApprovalMatchInput) (*domain.EgressRequest, error)
	HasDeniedPattern(ctx context.Context, in ApprovalMatchInput) (bool, error)
	MarkApprovalConsumed(ctx context.Context, id string) error
}

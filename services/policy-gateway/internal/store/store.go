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

type Store interface {
	Ping(ctx context.Context) error
	ListPendingRequests(ctx context.Context) ([]domain.EgressRequest, error)
	ListRules(ctx context.Context) ([]domain.PolicyRule, error)
	MatchRules(ctx context.Context, in MatchRulesInput) ([]domain.PolicyRule, error)
	CreateEgressRequest(ctx context.Context, in CreateEgressRequestInput) (domain.EgressRequest, error)
	InsertAuditEvent(ctx context.Context, egressRequestID, eventType, actorID string, metadata map[string]any) error
}

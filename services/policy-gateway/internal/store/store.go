package store

import (
	"context"

	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/domain"
)

type Store interface {
	Ping(ctx context.Context) error
	ListPendingRequests(ctx context.Context) ([]domain.EgressRequest, error)
	ListRules(ctx context.Context) ([]domain.PolicyRule, error)
}

package service

import (
	"context"

	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/store"
)

type EgressService struct {
	store store.Store
}

func NewEgress(st store.Store) *EgressService {
	return &EgressService{store: st}
}

func (s *EgressService) ListRequests(ctx context.Context, status domain.RequestStatus) ([]domain.EgressRequest, error) {
	switch status {
	case "", domain.RequestStatusPending:
		return s.store.ListPendingRequests(ctx)
	default:
		return nil, domain.InvalidEnumError{Field: "status", Value: string(status)}
	}
}

func (s *EgressService) ListRules(ctx context.Context) ([]domain.PolicyRule, error) {
	return s.store.ListRules(ctx)
}

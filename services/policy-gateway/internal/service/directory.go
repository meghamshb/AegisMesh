package service

import (
	"context"
	"strings"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
)

func (s *EgressService) GetOrganization(ctx context.Context, id string) (domain.Organization, error) {
	return s.store.GetOrganization(ctx, id)
}

type ListUsersOptions struct {
	Status string
}

func (s *EgressService) ListUsers(ctx context.Context, opts ListUsersOptions) ([]domain.User, error) {
	status := strings.TrimSpace(opts.Status)
	if status != "" && status != "active" && status != "disabled" {
		return nil, domain.InvalidEnumError{Field: "status", Value: status}
	}
	return s.store.ListUsers(ctx, store.ListUsersInput{Status: status})
}

func (s *EgressService) GetUser(ctx context.Context, id string) (domain.User, error) {
	return s.store.GetUser(ctx, id)
}

type ListAgentsOptions struct {
	UserID string
	Status string
}

func (s *EgressService) ListAgents(ctx context.Context, opts ListAgentsOptions) ([]domain.Agent, error) {
	status := strings.TrimSpace(opts.Status)
	if status != "" && status != "active" && status != "revoked" {
		return nil, domain.InvalidEnumError{Field: "status", Value: status}
	}
	return s.store.ListAgents(ctx, store.ListAgentsInput{
		UserID: strings.TrimSpace(opts.UserID),
		Status: status,
	})
}

func (s *EgressService) GetAgent(ctx context.Context, id string) (domain.Agent, error) {
	return s.store.GetAgent(ctx, id)
}

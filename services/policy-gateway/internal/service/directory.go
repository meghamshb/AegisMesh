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
	Limit  int
	Offset int
}

func (s *EgressService) ListUsers(ctx context.Context, opts ListUsersOptions) ([]domain.User, error) {
	status := strings.TrimSpace(opts.Status)
	if status != "" && status != "active" && status != "disabled" {
		return nil, domain.InvalidEnumError{Field: "status", Value: status}
	}
	return s.store.ListUsers(ctx, store.ListUsersInput{Status: status, Limit: opts.Limit, Offset: opts.Offset})
}

func (s *EgressService) GetUser(ctx context.Context, id string) (domain.User, error) {
	return s.store.GetUser(ctx, id)
}

var validRoles = map[string]bool{
	domain.RoleAdmin:    true,
	domain.RoleApprover: true,
	domain.RoleMember:   true,
}

func (s *EgressService) CreateUser(ctx context.Context, orgID string, body domain.CreateUserBody) (domain.User, error) {
	displayName := strings.TrimSpace(body.DisplayName)
	if displayName == "" {
		return domain.User{}, domain.InvalidEnumError{Field: "display_name", Value: ""}
	}
	role := strings.TrimSpace(body.Role)
	if role == "" {
		role = domain.RoleMember
	}
	if !validRoles[role] {
		return domain.User{}, domain.InvalidEnumError{Field: "role", Value: role}
	}

	return s.store.CreateUser(ctx, store.CreateUserInput{
		OrgID:       orgID,
		DisplayName: displayName,
		Email:       body.Email,
		Role:        role,
	})
}

func (s *EgressService) UpdateUser(ctx context.Context, id string, body domain.UpdateUserBody) (domain.User, error) {
	in := store.UpdateUserInput{Email: body.Email}
	if body.DisplayName != nil {
		trimmed := strings.TrimSpace(*body.DisplayName)
		if trimmed == "" {
			return domain.User{}, domain.InvalidEnumError{Field: "display_name", Value: ""}
		}
		in.DisplayName = &trimmed
	}
	if body.Role != nil {
		role := strings.TrimSpace(*body.Role)
		if !validRoles[role] {
			return domain.User{}, domain.InvalidEnumError{Field: "role", Value: role}
		}
		in.Role = &role
	}
	if body.Status != nil {
		status := strings.TrimSpace(*body.Status)
		if status != "active" && status != "disabled" {
			return domain.User{}, domain.InvalidEnumError{Field: "status", Value: status}
		}
		in.Status = &status
	}

	return s.store.UpdateUser(ctx, id, in)
}

type ListAgentsOptions struct {
	UserID string
	Status string
	Limit  int
	Offset int
}

func (s *EgressService) ListAgents(ctx context.Context, opts ListAgentsOptions) ([]domain.Agent, error) {
	status := strings.TrimSpace(opts.Status)
	if status != "" && status != "active" && status != "revoked" {
		return nil, domain.InvalidEnumError{Field: "status", Value: status}
	}
	return s.store.ListAgents(ctx, store.ListAgentsInput{
		UserID: strings.TrimSpace(opts.UserID),
		Status: status,
		Limit:  opts.Limit,
		Offset: opts.Offset,
	})
}

func (s *EgressService) GetAgent(ctx context.Context, id string) (domain.Agent, error) {
	return s.store.GetAgent(ctx, id)
}

func (s *EgressService) UpdateAgent(ctx context.Context, id string, body domain.UpdateAgentBody) (domain.Agent, error) {
	in := store.UpdateAgentInput{ContainerID: body.ContainerID, Metadata: body.Metadata}
	if body.Name != nil {
		trimmed := strings.TrimSpace(*body.Name)
		if trimmed == "" {
			return domain.Agent{}, domain.InvalidEnumError{Field: "name", Value: ""}
		}
		in.Name = &trimmed
	}
	return s.store.UpdateAgent(ctx, id, in)
}

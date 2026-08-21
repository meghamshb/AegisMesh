package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/identity"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/service"
)

func (s *Server) handleGetCurrentOrganization(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	org, err := s.egress.GetOrganization(ctx, principal.OrgID)
	if err != nil {
		s.handleDirectoryError(w, err)
		return
	}

	s.writeJSON(w, http.StatusOK, org)
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r)
	if !ok {
		return
	}
	limit, offset, err := paginationParams(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	users, err := s.egress.ListUsers(ctx, principal.OrgID, service.ListUsersOptions{
		Status: r.URL.Query().Get("status"),
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		var invalid domain.InvalidEnumError
		if errors.As(err, &invalid) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.logger.Error("list users", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to list users")
		return
	}

	s.writePaginated(w, users, len(users), limit, offset)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r)
	if !ok {
		return
	}
	if !principal.CanManageUsers() {
		s.writeError(w, http.StatusForbidden, "not authorized to create users")
		return
	}

	var body domain.CreateUserBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	user, err := s.egress.CreateUser(ctx, principal.OrgID, body)
	if err != nil {
		var invalid domain.InvalidEnumError
		if errors.As(err, &invalid) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.logger.Error("create user", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	s.writeJSON(w, http.StatusCreated, user)
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r)
	if !ok {
		return
	}
	if !principal.CanManageUsers() {
		s.writeError(w, http.StatusForbidden, "not authorized to update users")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "user id is required")
		return
	}

	var body domain.UpdateUserBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	user, err := s.egress.UpdateUser(ctx, principal.OrgID, id, body)
	if err != nil {
		var invalid domain.InvalidEnumError
		if errors.As(err, &invalid) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.handleDirectoryError(w, err)
		return
	}

	s.writeJSON(w, http.StatusOK, user)
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "user id is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	user, err := s.egress.GetUser(ctx, principal.OrgID, id)
	if err != nil {
		s.handleDirectoryError(w, err)
		return
	}

	s.writeJSON(w, http.StatusOK, user)
}

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r)
	if !ok {
		return
	}
	limit, offset, err := paginationParams(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	agents, err := s.egress.ListAgents(ctx, principal.OrgID, service.ListAgentsOptions{
		UserID: r.URL.Query().Get("user_id"),
		Status: r.URL.Query().Get("status"),
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		var invalid domain.InvalidEnumError
		if errors.As(err, &invalid) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.logger.Error("list agents", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to list agents")
		return
	}

	s.writePaginated(w, agents, len(agents), limit, offset)
}

func (s *Server) handleGetAgent(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "agent id is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	agent, err := s.egress.GetAgent(ctx, principal.OrgID, id)
	if err != nil {
		s.handleDirectoryError(w, err)
		return
	}

	s.writeJSON(w, http.StatusOK, agent)
}

func (s *Server) handleUpdateAgent(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "agent id is required")
		return
	}

	var body domain.UpdateAgentBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	agent, err := s.egress.GetAgent(ctx, principal.OrgID, id)
	if err != nil {
		s.handleDirectoryError(w, err)
		return
	}
	if !principal.CanManageAgent(agent.OwnerUserID) {
		s.writeError(w, http.StatusForbidden, "not authorized to update this agent")
		return
	}

	updated, err := s.egress.UpdateAgent(ctx, principal.OrgID, id, body)
	if err != nil {
		var invalid domain.InvalidEnumError
		if errors.As(err, &invalid) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.handleDirectoryError(w, err)
		return
	}

	s.writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleRegisterAgent(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r)
	if !ok {
		return
	}

	var body domain.RegisterAgentBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	body.OwnerUserID = strings.TrimSpace(body.OwnerUserID)
	body.Name = strings.TrimSpace(body.Name)
	if body.OwnerUserID == "" {
		s.writeError(w, http.StatusBadRequest, "owner_user_id is required")
		return
	}
	if body.Name == "" {
		s.writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// org_id comes from the authenticated principal, never the request body,
	// and the owner lookup is scoped to it - so an owner UUID from another
	// tenant reads as simply unknown. The store re-checks this inside the
	// insert transaction as well.
	owner, err := s.egress.GetUser(ctx, principal.OrgID, body.OwnerUserID)
	if err != nil {
		var notFound domain.ErrNotFound
		if errors.As(err, &notFound) {
			s.writeError(w, http.StatusBadRequest, "owner_user_id does not reference a known user")
			return
		}
		s.logger.Error("register agent: look up owner", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to register agent")
		return
	}

	agent, token, cred, err := s.identity.RegisterAgent(ctx, identity.RegisterAgentInput{
		OrgID:       principal.OrgID,
		OwnerUserID: owner.ID,
		Name:        body.Name,
		ContainerID: body.ContainerID,
		Metadata:    body.Metadata,
	}, principal.ActorID)
	if err != nil {
		s.logger.Error("register agent", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to register agent")
		return
	}

	s.writeJSON(w, http.StatusCreated, map[string]any{
		"agent": agent,
		"credential": map[string]any{
			"token":        token,
			"token_prefix": cred.TokenPrefix,
			"created_at":   cred.CreatedAt,
		},
	})
}

func (s *Server) handleRotateAgentCredential(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "agent id is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Rotation hands back a live agent token, so the org-scoped lookup here is
	// load-bearing, not cosmetic: an agent id from another tenant must 404
	// before any credential is minted. RotateCredential re-checks in-transaction.
	agent, err := s.egress.GetAgent(ctx, principal.OrgID, id)
	if err != nil {
		s.handleDirectoryError(w, err)
		return
	}
	if !principal.CanManageAgent(agent.OwnerUserID) {
		s.writeError(w, http.StatusForbidden, "not authorized to rotate this agent's credential")
		return
	}

	token, cred, err := s.identity.RotateCredential(ctx, principal.OrgID, id, principal.ActorID)
	if err != nil {
		s.logger.Error("rotate agent credential", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to rotate agent credential")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"agent_id": id,
		"credential": map[string]any{
			"token":        token,
			"token_prefix": cred.TokenPrefix,
			"created_at":   cred.CreatedAt,
		},
	})
}

func (s *Server) handleRevokeAgent(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "agent id is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	agent, err := s.identity.RevokeAgent(ctx, principal.OrgID, id, principal.ActorID)
	if err != nil {
		var notFound domain.ErrNotFound
		if errors.As(err, &notFound) {
			s.writeError(w, http.StatusNotFound, err.Error())
			return
		}
		s.logger.Error("revoke agent", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to revoke agent")
		return
	}

	s.writeJSON(w, http.StatusOK, agent)
}

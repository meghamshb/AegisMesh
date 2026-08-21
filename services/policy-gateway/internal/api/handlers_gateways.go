package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/identity"
)

func (s *Server) handleRegisterGateway(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r)
	if !ok {
		return
	}
	if !s.allowMutation(w, r) {
		return
	}

	var body domain.RegisterGatewayBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		s.writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	gw, token, err := s.identity.RegisterGateway(ctx, identity.RegisterGatewayInput{
		OrgID:    principal.OrgID,
		Name:     body.Name,
		Metadata: body.Metadata,
	})
	if err != nil {
		s.logger.Error("register gateway", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to register gateway")
		return
	}

	s.writeJSON(w, http.StatusCreated, map[string]any{
		"gateway": gw,
		"credential": map[string]any{
			"token":        token,
			"token_prefix": gw.CredentialPrefix,
			"created_at":   gw.CreatedAt,
		},
	})
}

func (s *Server) handleListGateways(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	gateways, err := s.egress.ListGateways(ctx, principal.OrgID)
	if err != nil {
		s.logger.Error("list gateways", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to list gateways")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{"items": gateways})
}

func (s *Server) handleGetGateway(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "gateway id is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	gw, err := s.egress.GetGateway(ctx, principal.OrgID, id)
	if err != nil {
		s.handleDirectoryError(w, err)
		return
	}

	s.writeJSON(w, http.StatusOK, gw)
}

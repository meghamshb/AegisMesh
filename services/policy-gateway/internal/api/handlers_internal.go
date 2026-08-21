package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/identity"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
)

// authorizeGateway validates the Authorization: Bearer <clr_gateway_...>
// header against a real, active gateway credential. Unlike authorizeAdmin
// this always requires a valid credential - there is no "auth disabled"
// escape hatch for the internal gateway-to-control-plane surface.
func (s *Server) authorizeGateway(w http.ResponseWriter, r *http.Request) (domain.AuthenticatedGateway, bool) {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	var token string
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		token = strings.TrimSpace(authHeader[len("Bearer "):])
	}
	if token == "" {
		s.writeError(w, http.StatusUnauthorized, "gateway credential required")
		return domain.AuthenticatedGateway{}, false
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	authed, err := s.identity.AuthenticateGatewayToken(ctx, token)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "invalid or revoked gateway credential")
		return domain.AuthenticatedGateway{}, false
	}
	return authed, true
}

func (s *Server) handleGatewayHeartbeat(w http.ResponseWriter, r *http.Request) {
	authed, ok := s.authorizeGateway(w, r)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	// The credential must belong to the gateway named in the URL - a valid
	// Gateway A credential must never be usable to heartbeat as Gateway B.
	if id == "" || id != authed.GatewayID {
		s.writeError(w, http.StatusForbidden, "credential does not match gateway id")
		return
	}

	var body domain.GatewayHeartbeatBody
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			s.writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	gw, err := s.identity.Heartbeat(ctx, authed.OrgID, id, store.GatewayHeartbeatInput{Version: body.Version})
	if err != nil {
		s.logger.Error("gateway heartbeat", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to record heartbeat")
		return
	}

	s.writeJSON(w, http.StatusOK, gw)
}

func (s *Server) handlePolicySnapshot(w http.ResponseWriter, r *http.Request) {
	authed, ok := s.authorizeGateway(w, r)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	version, err := s.egress.GetOrgPolicyVersion(ctx, authed.OrgID)
	if err != nil {
		s.logger.Error("get org policy version", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to build policy snapshot")
		return
	}
	rules, err := s.egress.ListRulesForOrgSnapshot(ctx, authed.OrgID)
	if err != nil {
		s.logger.Error("list org policy rules for snapshot", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to build policy snapshot")
		return
	}

	s.writeJSON(w, http.StatusOK, domain.PolicySnapshot{
		OrgID:       authed.OrgID,
		Version:     version,
		GeneratedAt: time.Now().UTC(),
		Rules:       rules,
	})
}

func (s *Server) handleInternalAuthenticateAgent(w http.ResponseWriter, r *http.Request) {
	authed, ok := s.authorizeGateway(w, r)
	if !ok {
		return
	}

	var body struct {
		TokenHash string `json:"token_hash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(body.TokenHash) == "" {
		s.writeError(w, http.StatusBadRequest, "token_hash is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	resolved, err := s.identity.AuthenticateAgentTokenHash(ctx, strings.TrimSpace(body.TokenHash))
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrInvalidToken), errors.Is(err, identity.ErrCredentialRevoked):
			s.writeError(w, http.StatusUnauthorized, "invalid or revoked agent credential")
		case errors.Is(err, identity.ErrAgentRevoked), errors.Is(err, identity.ErrOwnerDisabled), errors.Is(err, identity.ErrOrgSuspended):
			s.writeError(w, http.StatusForbidden, err.Error())
		default:
			s.logger.Error("internal authenticate agent", "error", err)
			s.writeError(w, http.StatusInternalServerError, "failed to authenticate agent")
		}
		return
	}

	// A gateway serves exactly one org, so it must not be able to resolve an
	// agent belonging to a different tenant - otherwise a valid gateway
	// credential would double as a cross-org identity oracle. Report it the
	// same as an unknown token.
	if resolved.OrgID != authed.OrgID {
		s.logger.Warn("gateway attempted cross-org agent authentication",
			"gateway_id", authed.GatewayID,
			"gateway_org_id", authed.OrgID,
			"agent_org_id", resolved.OrgID,
		)
		s.writeError(w, http.StatusUnauthorized, "invalid or revoked agent credential")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"agent_id":     resolved.AgentID,
		"user_id":      resolved.OwnerUserID,
		"org_id":       resolved.OrgID,
		"agent_status": "active",
		"user_status":  "active",
		"org_status":   "active",
	})
}

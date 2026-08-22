package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/service"
)

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r)
	if !ok {
		return
	}
	limit, offset, err := paginationParams(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var active *bool
	if raw := strings.TrimSpace(r.URL.Query().Get("active")); raw != "" {
		parsed, convErr := strconv.ParseBool(raw)
		if convErr != nil {
			s.writeError(w, http.StatusBadRequest, "active must be true or false")
			return
		}
		active = &parsed
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rules, err := s.egress.ListRules(ctx, principal.OrgID, service.ListRulesOptions{
		Scope:      strings.TrimSpace(r.URL.Query().Get("scope")),
		ScopeRefID: strings.TrimSpace(r.URL.Query().Get("scope_ref_id")),
		Effect:     strings.TrimSpace(r.URL.Query().Get("effect")),
		Host:       strings.TrimSpace(r.URL.Query().Get("host")),
		Active:     active,
		Limit:      limit,
		Offset:     offset,
	})
	if err != nil {
		s.logger.Error("list policy rules", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to list rules")
		return
	}

	s.writePaginated(w, rules, len(rules), limit, offset)
}

func (s *Server) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r)
	if !ok {
		return
	}
	if !s.allowMutation(w, r) {
		return
	}

	var body domain.CreatePolicyRuleBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	scopeForAuthz := body.Scope
	if scopeForAuthz == "" {
		scopeForAuthz = domain.RuleScopeOrg
	}
	if !principal.CanCreateRule(scopeForAuthz) {
		s.writeError(w, http.StatusForbidden, "not authorized to create a rule at this scope")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rule, err := s.egress.CreateRule(ctx, principal.OrgID, principal.ActorID, body)
	if err != nil {
		var invalid domain.InvalidEnumError
		if errors.As(err, &invalid) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		var connectBlocked domain.ErrRuleCONNECTNotAllowed
		if errors.As(err, &connectBlocked) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		var expiresPast domain.ErrExpiresAtInPast
		if errors.As(err, &expiresPast) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		var scopeRef domain.ErrInvalidScopeRef
		if errors.As(err, &scopeRef) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		var exists domain.ErrRuleAlreadyExists
		if errors.As(err, &exists) {
			s.writeError(w, http.StatusConflict, err.Error())
			return
		}
		s.logger.Error("create policy rule", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to create rule")
		return
	}

	s.writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r)
	if !ok {
		return
	}
	if !s.allowMutation(w, r) {
		return
	}
	if !principal.CanRevokeRule() {
		s.writeError(w, http.StatusForbidden, "not authorized to revoke rules")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "rule id is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if err := s.egress.RevokeRule(ctx, principal.OrgID, id, principal.ActorID); err != nil {
		var notFound domain.ErrNotFound
		if errors.As(err, &notFound) {
			s.writeError(w, http.StatusNotFound, err.Error())
			return
		}
		s.logger.Error("revoke policy rule", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to revoke rule")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r)
	if !ok {
		return
	}
	limit, offset, err := paginationParams(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	from, err := parseTimeParam(r, "from")
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	to, err := parseTimeParam(r, "to")
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	events, err := s.egress.ListAuditEvents(ctx, principal.OrgID, service.ListAuditEventsOptions{
		EventType: strings.TrimSpace(r.URL.Query().Get("event_type")),
		ActorID:   strings.TrimSpace(r.URL.Query().Get("actor_id")),
		From:      from,
		To:        to,
		Limit:     limit,
		Offset:    offset,
	})
	if err != nil {
		s.logger.Error("list audit events", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to list audit events")
		return
	}

	s.writePaginated(w, events, len(events), limit, offset)
}

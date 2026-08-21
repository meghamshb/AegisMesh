package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/config"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/identity"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/service"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/ui"
)

type Server struct {
	cfg      config.Config
	logger   *slog.Logger
	store    store.Store
	egress   *service.EgressService
	identity *identity.Service
	mux      *http.ServeMux
}

func New(cfg config.Config, logger *slog.Logger, st store.Store, egress *service.EgressService, identitySvc *identity.Service) *Server {
	s := &Server{
		cfg:      cfg,
		logger:   logger,
		store:    st,
		egress:   egress,
		identity: identitySvc,
		mux:      http.NewServeMux(),
	}
	s.registerRoutes()
	ui.NewHandler().Register(s.mux)
	return s
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /health", s.handleHealth)
	s.mux.HandleFunc("GET /api/v1/requests", s.handleListRequests)
	s.mux.HandleFunc("GET /api/v1/rules", s.handleListRules)
	s.mux.HandleFunc("GET /api/v1/audit", s.handleListAudit)
	s.mux.HandleFunc("GET /api/v1/requests/{id}", s.handleGetRequest)
	s.mux.HandleFunc("POST /api/v1/requests/{id}/approve", s.handleApproveRequest)
	s.mux.HandleFunc("POST /api/v1/requests/{id}/deny", s.handleDenyRequest)
	s.mux.HandleFunc("POST /api/v1/rules", s.handleCreateRule)
	s.mux.HandleFunc("DELETE /api/v1/rules/{id}", s.handleDeleteRule)
	s.mux.HandleFunc("GET /api/v1/organizations/current", s.handleGetCurrentOrganization)
	s.mux.HandleFunc("GET /api/v1/users", s.handleListUsers)
	s.mux.HandleFunc("POST /api/v1/users", s.handleCreateUser)
	s.mux.HandleFunc("GET /api/v1/users/{id}", s.handleGetUser)
	s.mux.HandleFunc("PATCH /api/v1/users/{id}", s.handleUpdateUser)
	s.mux.HandleFunc("GET /api/v1/agents", s.handleListAgents)
	s.mux.HandleFunc("GET /api/v1/agents/{id}", s.handleGetAgent)
	s.mux.HandleFunc("PATCH /api/v1/agents/{id}", s.handleUpdateAgent)
	s.mux.HandleFunc("POST /api/v1/agents", s.handleRegisterAgent)
	s.mux.HandleFunc("POST /api/v1/agents/{id}/credentials/rotate", s.handleRotateAgentCredential)
	s.mux.HandleFunc("POST /api/v1/agents/{id}/revoke", s.handleRevokeAgent)
	s.mux.HandleFunc("POST /api/v1/gateways", s.handleRegisterGateway)
	s.mux.HandleFunc("GET /api/v1/gateways", s.handleListGateways)
	s.mux.HandleFunc("GET /api/v1/gateways/{id}", s.handleGetGateway)

	// /api/internal/v1/* is the gateway-to-control-plane surface (Phase 5.9).
	// It is never exposed to the browser and is gated by a gateway
	// credential (authorizeGateway), not the admin token.
	s.mux.HandleFunc("POST /api/internal/v1/gateways/{id}/heartbeat", s.handleGatewayHeartbeat)
	s.mux.HandleFunc("GET /api/internal/v1/policies/snapshot", s.handlePolicySnapshot)
	s.mux.HandleFunc("POST /api/internal/v1/agents/authenticate", s.handleInternalAuthenticateAgent)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{
		"postgres": "ok",
		"proxy":    proxyState(s.cfg.ProxyEnabled),
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := s.store.Ping(ctx); err != nil {
		checks["postgres"] = "unavailable"
		s.writeJSON(w, http.StatusServiceUnavailable, domain.HealthStatus{
			Status:  "degraded",
			Service: s.cfg.ServiceName,
			Version: s.cfg.ServiceVersion,
			Checks:  checks,
		})
		return
	}

	s.writeJSON(w, http.StatusOK, domain.HealthStatus{
		Status:  "ok",
		Service: s.cfg.ServiceName,
		Version: s.cfg.ServiceVersion,
		Checks:  checks,
	})
}

func proxyState(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

func (s *Server) handleListRequests(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
		return
	}

	statusFilter := domain.RequestStatus(strings.TrimSpace(r.URL.Query().Get("status")))
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

	requests, err := s.egress.ListRequests(ctx, service.ListRequestsOptions{
		Status:  statusFilter,
		Host:    strings.TrimSpace(r.URL.Query().Get("host")),
		UserID:  strings.TrimSpace(r.URL.Query().Get("user_id")),
		AgentID: strings.TrimSpace(r.URL.Query().Get("agent_id")),
		From:    from,
		To:      to,
		Limit:   limit,
		Offset:  offset,
	})
	if err != nil {
		var invalid domain.InvalidEnumError
		if errors.As(err, &invalid) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.logger.Error("list requests", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to list requests")
		return
	}

	s.writePaginated(w, requests, len(requests), limit, offset)
}

func (s *Server) handleGetRequest(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "request id is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	req, err := s.egress.GetRequest(ctx, id)
	if err != nil {
		s.handleRequestError(w, err)
		return
	}

	s.writeJSON(w, http.StatusOK, req)
}

func (s *Server) handleApproveRequest(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "request id is required")
		return
	}

	var body domain.ApproveRequestBody
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			s.writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}

	if body.Remember && s.cfg.AdminToken == "" {
		s.writeError(w, http.StatusForbidden, domain.ErrRememberRequiresAuth{}.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	approved, err := s.egress.Approve(ctx, id, s.approverID(r), body)
	if err != nil {
		var unsupported domain.ErrRememberScopeNotSupported
		if errors.As(err, &unsupported) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		var connectBlocked domain.ErrRememberCONNECTNotAllowed
		if errors.As(err, &connectBlocked) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		var expiresPast domain.ErrExpiresAtInPast
		if errors.As(err, &expiresPast) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.handleRequestError(w, err)
		return
	}

	s.writeJSON(w, http.StatusOK, approved)
}

func (s *Server) handleDenyRequest(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "request id is required")
		return
	}

	var body domain.DenyRequestBody
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			s.writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	denied, err := s.egress.Deny(ctx, id, s.approverID(r), body.Feedback)
	if err != nil {
		s.handleRequestError(w, err)
		return
	}

	s.writeJSON(w, http.StatusOK, denied)
}

func (s *Server) handleRequestError(w http.ResponseWriter, err error) {
	var notFound domain.ErrNotFound
	if errors.As(err, &notFound) {
		s.writeError(w, http.StatusNotFound, err.Error())
		return
	}

	var notPending domain.ErrRequestNotPending
	if errors.As(err, &notPending) {
		s.writeError(w, http.StatusConflict, err.Error())
		return
	}

	s.logger.Error("request handler", "error", err)
	s.writeError(w, http.StatusInternalServerError, "request operation failed")
}

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
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

	rules, err := s.egress.ListRules(ctx, service.ListRulesOptions{
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

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
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

	events, err := s.egress.ListAuditEvents(ctx, service.ListAuditEventsOptions{
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

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "rule id is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if err := s.egress.RevokeRule(ctx, id, s.approverID(r)); err != nil {
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

func (s *Server) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
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
	if !s.currentPrincipal(r).CanCreateRule(scopeForAuthz) {
		s.writeError(w, http.StatusForbidden, "not authorized to create a rule at this scope")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rule, err := s.egress.CreateRule(ctx, s.cfg.Identity.OrgID, s.approverID(r), body)
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

func (s *Server) handleGetCurrentOrganization(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	org, err := s.egress.GetOrganization(ctx, s.cfg.Identity.OrgID)
	if err != nil {
		s.handleDirectoryError(w, err)
		return
	}

	s.writeJSON(w, http.StatusOK, org)
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
		return
	}
	limit, offset, err := paginationParams(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	users, err := s.egress.ListUsers(ctx, service.ListUsersOptions{
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
	if !s.authorizeAdmin(w, r) {
		return
	}
	if !s.currentPrincipal(r).CanManageUsers() {
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

	user, err := s.egress.CreateUser(ctx, s.cfg.Identity.OrgID, body)
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
	if !s.authorizeAdmin(w, r) {
		return
	}
	if !s.currentPrincipal(r).CanManageUsers() {
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

	user, err := s.egress.UpdateUser(ctx, id, body)
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
	if !s.authorizeAdmin(w, r) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "user id is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	user, err := s.egress.GetUser(ctx, id)
	if err != nil {
		s.handleDirectoryError(w, err)
		return
	}

	s.writeJSON(w, http.StatusOK, user)
}

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
		return
	}
	limit, offset, err := paginationParams(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	agents, err := s.egress.ListAgents(ctx, service.ListAgentsOptions{
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

func (s *Server) handleUpdateAgent(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
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

	agent, err := s.egress.GetAgent(ctx, id)
	if err != nil {
		s.handleDirectoryError(w, err)
		return
	}
	if !s.currentPrincipal(r).CanManageAgent(agent.OwnerUserID) {
		s.writeError(w, http.StatusForbidden, "not authorized to update this agent")
		return
	}

	updated, err := s.egress.UpdateAgent(ctx, id, body)
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

func (s *Server) handleGetAgent(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "agent id is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	agent, err := s.egress.GetAgent(ctx, id)
	if err != nil {
		s.handleDirectoryError(w, err)
		return
	}

	s.writeJSON(w, http.StatusOK, agent)
}

func (s *Server) handleRegisterAgent(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
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

	// org_id is derived from the gateway's configured org, not accepted from
	// the request body, so a caller cannot register an agent into another org.
	owner, err := s.egress.GetUser(ctx, body.OwnerUserID)
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
	if owner.OrgID != s.cfg.Identity.OrgID {
		s.writeError(w, http.StatusBadRequest, "owner_user_id does not belong to this organization")
		return
	}

	agent, token, cred, err := s.identity.RegisterAgent(ctx, identity.RegisterAgentInput{
		OrgID:       s.cfg.Identity.OrgID,
		OwnerUserID: body.OwnerUserID,
		Name:        body.Name,
		ContainerID: body.ContainerID,
		Metadata:    body.Metadata,
	}, s.approverID(r))
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
	if !s.authorizeAdmin(w, r) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "agent id is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if _, err := s.egress.GetAgent(ctx, id); err != nil {
		s.handleDirectoryError(w, err)
		return
	}

	token, cred, err := s.identity.RotateCredential(ctx, id, s.approverID(r))
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
	if !s.authorizeAdmin(w, r) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "agent id is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	agent, err := s.identity.RevokeAgent(ctx, id, s.approverID(r))
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

func (s *Server) handleRegisterGateway(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
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
		OrgID:    s.cfg.Identity.OrgID,
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
	if !s.authorizeAdmin(w, r) {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	gateways, err := s.egress.ListGateways(ctx, s.cfg.Identity.OrgID)
	if err != nil {
		s.logger.Error("list gateways", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to list gateways")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{"items": gateways})
}

func (s *Server) handleGetGateway(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "gateway id is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	gw, err := s.egress.GetGateway(ctx, id)
	if err != nil {
		s.handleDirectoryError(w, err)
		return
	}

	s.writeJSON(w, http.StatusOK, gw)
}

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

	gw, err := s.identity.Heartbeat(ctx, id, store.GatewayHeartbeatInput{Version: body.Version})
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
	if _, ok := s.authorizeGateway(w, r); !ok {
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

	authed, err := s.identity.AuthenticateAgentTokenHash(ctx, strings.TrimSpace(body.TokenHash))
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

	s.writeJSON(w, http.StatusOK, map[string]any{
		"agent_id":     authed.AgentID,
		"user_id":      authed.OwnerUserID,
		"org_id":       authed.OrgID,
		"agent_status": "active",
		"user_status":  "active",
		"org_status":   "active",
	})
}

func (s *Server) handleDirectoryError(w http.ResponseWriter, err error) {
	var notFound domain.ErrNotFound
	if errors.As(err, &notFound) {
		s.writeError(w, http.StatusNotFound, err.Error())
		return
	}
	s.logger.Error("directory handler", "error", err)
	s.writeError(w, http.StatusInternalServerError, "directory operation failed")
}

func (s *Server) notImplemented(w http.ResponseWriter, _ *http.Request) {
	s.writeError(w, http.StatusNotImplemented, "not implemented in this phase")
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		s.logger.Error("encode json response", "error", err)
	}
}

func (s *Server) writeError(w http.ResponseWriter, status int, message string) {
	s.writeJSON(w, status, map[string]any{
		"error": map[string]string{
			"code":    errorCode(status),
			"message": message,
		},
	})
}

func errorCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "bad_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "conflict"
	case http.StatusProxyAuthRequired:
		return "proxy_authentication_required"
	case http.StatusNotImplemented:
		return "not_implemented"
	default:
		return "internal_error"
	}
}

// paginationParams parses limit/offset query params shared by every list
// endpoint. Default 50, capped at 200, matching the store layer's own clamp.
func paginationParams(r *http.Request) (limit, offset int, err error) {
	limit = 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, convErr := strconv.Atoi(raw)
		if convErr != nil || parsed <= 0 {
			return 0, 0, fmt.Errorf("limit must be a positive integer")
		}
		limit = parsed
	}
	if limit > 200 {
		limit = 200
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		parsed, convErr := strconv.Atoi(raw)
		if convErr != nil || parsed < 0 {
			return 0, 0, fmt.Errorf("offset must be a non-negative integer")
		}
		offset = parsed
	}
	return limit, offset, nil
}

// parseTimeParam parses an RFC3339 query parameter, returning nil if absent.
func parseTimeParam(r *http.Request, name string) (*time.Time, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, fmt.Errorf("%s must be RFC3339, got %q", name, raw)
	}
	return &parsed, nil
}

func (s *Server) writePaginated(w http.ResponseWriter, items any, count, limit, offset int) {
	s.writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
		"pagination": map[string]any{
			"limit":    limit,
			"offset":   offset,
			"returned": count,
		},
	})
}

// currentPrincipal builds the control-plane caller's identity. Until Phase
// 5.13 wires up real per-caller authentication, every request that passes
// authorizeAdmin is treated as a single org-wide admin - but handlers call
// through Principal's Can* methods rather than hardcoding that assumption,
// so swapping in real multi-principal auth later won't require touching them.
func (s *Server) currentPrincipal(r *http.Request) domain.Principal {
	return domain.Principal{
		ActorID: s.approverID(r),
		OrgID:   s.cfg.Identity.OrgID,
		Role:    domain.RoleAdmin,
	}
}

func (s *Server) authorizeAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.AdminToken == "" {
		return true
	}

	token := strings.TrimSpace(r.Header.Get("X-Admin-Token"))
	if token == "" {
		authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
		if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			token = strings.TrimSpace(authHeader[7:])
		}
	}
	if token != s.cfg.AdminToken {
		w.Header().Set("WWW-Authenticate", `Bearer realm="policy-gateway-admin"`)
		s.writeError(w, http.StatusUnauthorized, "admin token required")
		return false
	}
	return true
}

func (s *Server) approverID(r *http.Request) string {
	if header := strings.TrimSpace(r.Header.Get(s.cfg.ApproverHeader)); header != "" {
		return header
	}
	return s.cfg.AdminID
}

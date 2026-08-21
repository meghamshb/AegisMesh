// Package api serves the control plane (human-facing admin API) and the
// internal gateway-to-control-plane surface. Handlers are split by resource
// across handlers_*.go; this file owns the server itself, routing, auth, and
// the response helpers they share.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/auth"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/config"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/identity"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/ratelimit"
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

	// Rate limiters (Phase 5.11.2). authFailures throttles credential
	// guessing; mutations throttles the privileged operations that mint or
	// revoke access. Ordinary reads are not limited.
	authFailures *ratelimit.Limiter
	mutations    *ratelimit.Limiter

	// principals resolves an OIDC bearer token to a Principal. Nil in
	// dev-token mode, where the shared static token is used instead.
	principals *auth.Resolver
}

// WithPrincipalResolver installs the OIDC resolver used by
// CLEARANCE_AUTH_MODE=oidc. Kept as a setter rather than a New parameter so
// dev-token deployments construct the server exactly as before.
func (s *Server) WithPrincipalResolver(r *auth.Resolver) *Server {
	s.principals = r
	return s
}

func New(cfg config.Config, logger *slog.Logger, st store.Store, egress *service.EgressService, identitySvc *identity.Service) *Server {
	s := &Server{
		cfg:      cfg,
		logger:   logger,
		store:    st,
		egress:   egress,
		identity: identitySvc,
		mux:      http.NewServeMux(),

		authFailures: ratelimit.New(cfg.AuthFailureLimit, cfg.RateLimitWindow),
		mutations:    ratelimit.New(cfg.MutationLimit, cfg.RateLimitWindow),
	}
	s.registerRoutes()
	ui.NewHandler().Register(s.mux)
	return s
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

// HealthHandler exposes just the liveness endpoint, so a gateway-mode process
// can answer container healthchecks without also serving the control plane.
func (s *Server) HealthHandler() http.Handler {
	return http.HandlerFunc(s.handleHealth)
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /health", s.handleHealth)
	// Unauthenticated by design: the UI must be able to discover how to
	// authenticate before it has authenticated. It exposes only the mode and
	// public client configuration, never a secret.
	s.mux.HandleFunc("GET /api/v1/auth/config", s.handleAuthConfig)
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
	s.mux.HandleFunc("GET /api/internal/v1/gateways/self", s.handleGatewaySelf)
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

// requirePrincipal authenticates the control-plane caller and hands back their
// Principal. Every tenant-scoped handler starts here and takes the org it
// operates on from principal.OrgID - never from a request body, path, or query
// parameter, so a caller cannot name someone else's tenant.
//
// Which mode applies is decided by CLEARANCE_AUTH_MODE (Phase 5.13). Both
// modes converge on the same domain.Principal, so no handler and no policy
// code knows or cares which one authenticated the request.
func (s *Server) requirePrincipal(w http.ResponseWriter, r *http.Request) (domain.Principal, bool) {
	if s.cfg.AuthMode == config.AuthModeOIDC {
		return s.oidcPrincipal(w, r)
	}
	if !s.authorizeAdmin(w, r) {
		return domain.Principal{}, false
	}
	return s.devTokenPrincipal(r), true
}

// oidcPrincipal resolves a verified OIDC token to the actor it represents.
//
// The failure responses here are deliberately uniform: an unknown subject, a
// disabled user, and an ambiguous email all return 403 with a generic message.
// Distinguishing them would let an unauthenticated caller probe which
// identities exist in the deployment.
func (s *Server) oidcPrincipal(w http.ResponseWriter, r *http.Request) (domain.Principal, bool) {
	if s.principals == nil {
		s.logger.Error("oidc auth mode is configured but no principal resolver was installed")
		s.writeError(w, http.StatusInternalServerError, "authentication is misconfigured")
		return domain.Principal{}, false
	}

	token := bearerToken(r)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	principal, err := s.principals.Resolve(ctx, token)
	if err == nil {
		return principal, true
	}

	if !s.authFailures.Allow(ratelimit.ClientKey(r)) {
		s.writeError(w, http.StatusTooManyRequests, "too many authentication failures; retry later")
		return domain.Principal{}, false
	}

	switch {
	case errors.Is(err, auth.ErrNoCredential), errors.Is(err, auth.ErrInvalidToken):
		w.Header().Set("WWW-Authenticate", `Bearer realm="clearance", error="invalid_token"`)
		s.writeError(w, http.StatusUnauthorized, "a valid bearer token is required")
	default:
		// Verified identity, but not authorized to use this deployment.
		s.logger.Warn("rejected authenticated identity", "error", err)
		s.writeError(w, http.StatusForbidden, "this identity is not provisioned for access")
	}
	return domain.Principal{}, false
}

// devTokenPrincipal is the pre-5.13 behavior: a single shared admin token
// stands in for every operator, so there is exactly one principal and its org
// comes from process configuration rather than from the caller.
func (s *Server) devTokenPrincipal(r *http.Request) domain.Principal {
	return domain.Principal{
		ActorID: s.approverID(r),
		OrgID:   s.cfg.Identity.OrgID,
		Role:    domain.RoleAdmin,
	}
}

// currentPrincipal is retained for callers that only need the shape of the
// caller rather than a full authentication decision.
func (s *Server) currentPrincipal(r *http.Request) domain.Principal {
	return s.devTokenPrincipal(r)
}

func bearerToken(r *http.Request) string {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return ""
	}
	return strings.TrimSpace(header[len("Bearer "):])
}

func (s *Server) authorizeAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.AdminToken == "" {
		return true
	}

	token := strings.TrimSpace(r.Header.Get("X-Admin-Token"))
	if token == "" {
		token = bearerToken(r)
	}
	if token != s.cfg.AdminToken {
		// Count the failure before reporting it, so repeated guessing from one
		// source runs out of budget rather than being free.
		if !s.authFailures.Allow(ratelimit.ClientKey(r)) {
			s.writeError(w, http.StatusTooManyRequests, "too many authentication failures; retry later")
			return false
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="policy-gateway-admin"`)
		s.writeError(w, http.StatusUnauthorized, "admin token required")
		return false
	}
	return true
}

// allowMutation gates the privileged operations that mint or revoke access -
// agent registration, credential rotation, and approval decisions. Reads are
// deliberately not limited: an operator refreshing the console must never be
// throttled out of seeing pending requests.
func (s *Server) allowMutation(w http.ResponseWriter, r *http.Request) bool {
	if s.mutations.Allow(ratelimit.ClientKey(r)) {
		return true
	}
	s.writeError(w, http.StatusTooManyRequests, "too many privileged operations; retry later")
	return false
}

func (s *Server) approverID(r *http.Request) string {
	if header := strings.TrimSpace(r.Header.Get(s.cfg.ApproverHeader)); header != "" {
		return header
	}
	return s.cfg.AdminID
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

func (s *Server) handleDirectoryError(w http.ResponseWriter, err error) {
	var notFound domain.ErrNotFound
	if errors.As(err, &notFound) {
		s.writeError(w, http.StatusNotFound, err.Error())
		return
	}
	s.logger.Error("directory handler", "error", err)
	s.writeError(w, http.StatusInternalServerError, "directory operation failed")
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

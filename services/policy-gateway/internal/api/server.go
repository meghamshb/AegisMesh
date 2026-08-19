package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/config"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/service"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/store"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/ui"
)

type Server struct {
	cfg    config.Config
	logger *slog.Logger
	store  store.Store
	egress *service.EgressService
	mux    *http.ServeMux
}

func New(cfg config.Config, logger *slog.Logger, st store.Store, egress *service.EgressService) *Server {
	s := &Server{
		cfg:    cfg,
		logger: logger,
		store:  st,
		egress: egress,
		mux:    http.NewServeMux(),
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
	s.mux.HandleFunc("POST /api/v1/rules", s.notImplemented)
	s.mux.HandleFunc("DELETE /api/v1/rules/{id}", s.handleDeleteRule)
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
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			s.writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		if parsed > 500 {
			parsed = 500
		}
		limit = parsed
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	requests, err := s.egress.ListRequests(ctx, service.ListRequestsOptions{
		Status:  statusFilter,
		Host:    strings.TrimSpace(r.URL.Query().Get("host")),
		UserID:  strings.TrimSpace(r.URL.Query().Get("user_id")),
		AgentID: strings.TrimSpace(r.URL.Query().Get("agent_id")),
		Limit:   limit,
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

	s.writeJSON(w, http.StatusOK, map[string]any{"items": requests})
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
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rules, err := s.egress.ListRules(ctx)
	if err != nil {
		s.logger.Error("list policy rules", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to list rules")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{"items": rules})
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	events, err := s.egress.ListAuditEvents(ctx)
	if err != nil {
		s.logger.Error("list audit events", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to list audit events")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{"items": events})
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
	s.writeJSON(w, status, map[string]string{"error": message})
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

package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/config"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/service"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/store"
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
	return s
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /health", s.handleHealth)
	s.mux.HandleFunc("GET /api/v1/requests", s.handleListRequests)
	s.mux.HandleFunc("GET /api/v1/rules", s.handleListRules)
	s.mux.HandleFunc("GET /api/v1/audit", s.notImplemented)
	s.mux.HandleFunc("GET /api/v1/requests/{id}", s.notImplemented)
	s.mux.HandleFunc("POST /api/v1/requests/{id}/approve", s.notImplemented)
	s.mux.HandleFunc("POST /api/v1/requests/{id}/deny", s.notImplemented)
	s.mux.HandleFunc("POST /api/v1/rules", s.notImplemented)
	s.mux.HandleFunc("DELETE /api/v1/rules/{id}", s.notImplemented)
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
	statusFilter := domain.RequestStatus(strings.TrimSpace(r.URL.Query().Get("status")))

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	requests, err := s.egress.ListRequests(ctx, statusFilter)
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

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) notImplemented(w http.ResponseWriter, _ *http.Request) {
	s.writeError(w, http.StatusNotImplemented, "not implemented in phase 0")
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

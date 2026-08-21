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
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/service"
)

func (s *Server) handleListRequests(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r)
	if !ok {
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

	requests, err := s.egress.ListRequests(ctx, principal.OrgID, service.ListRequestsOptions{
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
	principal, ok := s.requirePrincipal(w, r)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "request id is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	req, err := s.egress.GetRequest(ctx, principal.OrgID, id)
	if err != nil {
		s.handleRequestError(w, err)
		return
	}

	s.writeJSON(w, http.StatusOK, req)
}

func (s *Server) handleApproveRequest(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r)
	if !ok {
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

	approved, err := s.egress.Approve(ctx, principal.OrgID, id, principal.ActorID, body)
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
	principal, ok := s.requirePrincipal(w, r)
	if !ok {
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

	denied, err := s.egress.Deny(ctx, principal.OrgID, id, principal.ActorID, body.Feedback)
	if err != nil {
		s.handleRequestError(w, err)
		return
	}

	s.writeJSON(w, http.StatusOK, denied)
}

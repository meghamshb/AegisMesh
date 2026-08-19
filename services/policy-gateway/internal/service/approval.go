package service

import (
	"context"
	"fmt"

	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/domain"
)

func (s *EgressService) GetRequest(ctx context.Context, id string) (domain.EgressRequest, error) {
	req, err := s.store.GetEgressRequest(ctx, id)
	if err != nil {
		return domain.EgressRequest{}, err
	}
	return req, nil
}

func (s *EgressService) ApproveOnce(ctx context.Context, requestID, adminID string, body domain.ApproveRequestBody) (domain.EgressRequest, error) {
	if body.Remember {
		return domain.EgressRequest{}, fmt.Errorf("remember=true org rules are implemented in phase 3")
	}

	approved, err := s.store.ApproveRequestOnce(ctx, requestID, adminID)
	if err != nil {
		return domain.EgressRequest{}, err
	}

	if err := s.store.InsertAuditEvent(ctx, approved.ID, "egress_approved_once", adminID, map[string]any{
		"host":   approved.Host,
		"port":   approved.Port,
		"method": approved.Method,
		"path":   approved.Path,
		"scope":  body.Scope,
	}); err != nil {
		return domain.EgressRequest{}, fmt.Errorf("insert approval audit event: %w", err)
	}

	return approved, nil
}

func (s *EgressService) Deny(ctx context.Context, requestID, adminID, feedback string) (domain.EgressRequest, error) {
	denied, err := s.store.DenyRequest(ctx, requestID, adminID, feedback)
	if err != nil {
		return domain.EgressRequest{}, err
	}

	metadata := map[string]any{
		"host":   denied.Host,
		"port":   denied.Port,
		"method": denied.Method,
		"path":   denied.Path,
	}
	if feedback != "" {
		metadata["feedback"] = feedback
	}
	if err := s.store.InsertAuditEvent(ctx, denied.ID, "egress_denied", adminID, metadata); err != nil {
		return domain.EgressRequest{}, fmt.Errorf("insert deny audit event: %w", err)
	}

	return denied, nil
}

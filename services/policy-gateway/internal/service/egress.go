package service

import (
	"context"
	"fmt"

	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/config"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/policy"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/store"
)

type EgressService struct {
	store  store.Store
	engine policy.Engine
}

func NewEgress(st store.Store, engine policy.Engine) *EgressService {
	return &EgressService{store: st, engine: engine}
}

func (s *EgressService) ListRequests(ctx context.Context, status domain.RequestStatus) ([]domain.EgressRequest, error) {
	switch status {
	case "", domain.RequestStatusPending:
		return s.store.ListPendingRequests(ctx)
	default:
		return nil, domain.InvalidEnumError{Field: "status", Value: string(status)}
	}
}

func (s *EgressService) ListRules(ctx context.Context) ([]domain.PolicyRule, error) {
	return s.store.ListRules(ctx)
}

func (s *EgressService) RecordOutbound(
	ctx context.Context,
	identity config.AgentIdentity,
	req policy.Request,
) (policy.Decision, domain.EgressRequest, error) {
	decision, ruleID, err := s.engine.Evaluate(ctx, req)
	if err != nil {
		return "", domain.EgressRequest{}, fmt.Errorf("evaluate policy: %w", err)
	}

	status, err := policy.DecisionToStatus(decision)
	if err != nil {
		return "", domain.EgressRequest{}, err
	}

	created, err := s.store.CreateEgressRequest(ctx, store.CreateEgressRequestInput{
		AgentID: identity.AgentID,
		UserID:  identity.UserID,
		OrgID:   identity.OrgID,
		Method:  req.Method,
		Host:    req.Host,
		Port:    req.Port,
		Path:    req.Path,
		Scheme:  req.Scheme,
		Status:  status,
		RuleID:  ruleID,
	})
	if err != nil {
		return "", domain.EgressRequest{}, fmt.Errorf("create egress request: %w", err)
	}

	eventType := auditEventType(decision)
	if err := s.store.InsertAuditEvent(ctx, created.ID, eventType, identity.UserID, map[string]any{
		"host":     req.Host,
		"port":     req.Port,
		"method":   req.Method,
		"path":     req.Path,
		"scheme":   req.Scheme,
		"decision": string(decision),
		"rule_id":  ruleID,
	}); err != nil {
		return "", domain.EgressRequest{}, fmt.Errorf("insert audit event: %w", err)
	}

	return decision, created, nil
}

func auditEventType(decision policy.Decision) string {
	switch decision {
	case policy.DecisionAllow:
		return "egress_auto_approved"
	case policy.DecisionDeny:
		return "egress_denied"
	default:
		return "egress_pending"
	}
}

package service

import (
	"context"
	"fmt"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/config"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/policy"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
)

type EgressService struct {
	store  store.Store
	engine policy.Engine
}

func NewEgress(st store.Store, engine policy.Engine) *EgressService {
	return &EgressService{store: st, engine: engine}
}

type ListRequestsOptions struct {
	Status  domain.RequestStatus
	Host    string
	UserID  string
	AgentID string
	From    *time.Time
	To      *time.Time
	Limit   int
	Offset  int
}

func (s *EgressService) ListRequests(ctx context.Context, opts ListRequestsOptions) ([]domain.EgressRequest, error) {
	in := store.ListRequestsInput{
		Host:    opts.Host,
		UserID:  opts.UserID,
		AgentID: opts.AgentID,
		From:    opts.From,
		To:      opts.To,
		Limit:   opts.Limit,
		Offset:  opts.Offset,
	}
	switch opts.Status {
	case "":
		return s.store.ListRequests(ctx, in)
	case domain.RequestStatusPending,
		domain.RequestStatusApproved,
		domain.RequestStatusDenied,
		domain.RequestStatusAutoApproved,
		domain.RequestStatusExpired:
		status := opts.Status
		in.Status = &status
		return s.store.ListRequests(ctx, in)
	default:
		return nil, domain.InvalidEnumError{Field: "status", Value: string(opts.Status)}
	}
}

type ListRulesOptions struct {
	Scope      string
	ScopeRefID string
	Effect     string
	Host       string
	Active     *bool
	Limit      int
	Offset     int
}

func (s *EgressService) ListRules(ctx context.Context, opts ListRulesOptions) ([]domain.PolicyRule, error) {
	return s.store.ListRules(ctx, store.ListRulesInput{
		Scope:      opts.Scope,
		ScopeRefID: opts.ScopeRefID,
		Effect:     opts.Effect,
		Host:       opts.Host,
		Active:     opts.Active,
		Limit:      opts.Limit,
		Offset:     opts.Offset,
	})
}

type ListAuditEventsOptions struct {
	EventType string
	ActorID   string
	From      *time.Time
	To        *time.Time
	Limit     int
	Offset    int
}

func (s *EgressService) ListAuditEvents(ctx context.Context, opts ListAuditEventsOptions) ([]domain.AuditEvent, error) {
	return s.store.ListAuditEvents(ctx, store.ListAuditEventsInput{
		EventType: opts.EventType,
		ActorID:   opts.ActorID,
		From:      opts.From,
		To:        opts.To,
		Limit:     opts.Limit,
		Offset:    opts.Offset,
	})
}

func (s *EgressService) RecordOutbound(
	ctx context.Context,
	identity config.AgentIdentity,
	req policy.Request,
) (policy.Decision, domain.EgressRequest, error) {
	req.AgentID = identity.AgentID
	req.UserID = identity.UserID
	req.OrgID = identity.OrgID

	eval, err := s.engine.Evaluate(ctx, req)
	if err != nil {
		return "", domain.EgressRequest{}, fmt.Errorf("evaluate policy: %w", err)
	}

	status, err := policy.StatusForEvaluation(eval)
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
		RuleID:  eval.RuleID,
	})
	if err != nil {
		return "", domain.EgressRequest{}, fmt.Errorf("create egress request: %w", err)
	}

	if eval.ApprovalGrantID != nil {
		if err := s.store.MarkApprovalConsumed(ctx, *eval.ApprovalGrantID); err != nil {
			return "", domain.EgressRequest{}, fmt.Errorf("consume one-time approval: %w", err)
		}
	}

	eventType := auditEventType(eval.Decision, eval.ApprovalGrantID)
	actorID := identity.UserID
	if eval.ApprovalGrantID != nil {
		actorID = ""
	}
	if err := s.store.InsertAuditEvent(ctx, created.ID, eventType, actorID, map[string]any{
		"host":              req.Host,
		"port":              req.Port,
		"method":            req.Method,
		"path":              req.Path,
		"scheme":            req.Scheme,
		"decision":          string(eval.Decision),
		"rule_id":           eval.RuleID,
		"approval_grant_id": eval.ApprovalGrantID,
	}); err != nil {
		return "", domain.EgressRequest{}, fmt.Errorf("insert audit event: %w", err)
	}

	return eval.Decision, created, nil
}

func auditEventType(decision policy.Decision, approvalGrantID *string) string {
	switch decision {
	case policy.DecisionAllow:
		if approvalGrantID != nil {
			return "egress_approved_once_consumed"
		}
		return "egress_auto_approved"
	case policy.DecisionDeny:
		return "egress_denied"
	default:
		return "egress_pending"
	}
}

package service

import (
	"context"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
)

func (s *EgressService) GetRequest(ctx context.Context, id string) (domain.EgressRequest, error) {
	req, err := s.store.GetEgressRequest(ctx, id)
	if err != nil {
		return domain.EgressRequest{}, err
	}
	return req, nil
}

func (s *EgressService) Approve(ctx context.Context, requestID, adminID string, body domain.ApproveRequestBody) (domain.EgressRequest, error) {
	if body.Remember {
		scope := body.Scope
		if scope == "" {
			scope = domain.RuleScopeOrg
		}
		if scope != domain.RuleScopeOrg && scope != domain.RuleScopeUser && scope != domain.RuleScopeAgent {
			return domain.EgressRequest{}, domain.ErrRememberScopeNotSupported{Scope: scope}
		}

		pending, err := s.store.GetEgressRequest(ctx, requestID)
		if err != nil {
			return domain.EgressRequest{}, err
		}
		// CONNECT tunnels only give Clearance hostname-level visibility, never
		// path-level, so a remembered CONNECT rule would silently over-authorize
		// at every scope. Keep this blocked regardless of scope (Phase 5.5.5).
		if pending.Method == "CONNECT" {
			return domain.EgressRequest{}, domain.ErrRememberCONNECTNotAllowed{Host: pending.Host}
		}
		if err := validateExpiresAt(body.ExpiresAt); err != nil {
			return domain.EgressRequest{}, err
		}

		// scope_ref_id is always derived from the pending request itself, never
		// accepted from the client: a caller can only remember a rule against
		// the org/user/agent that actually made this request.
		var scopeRefID string
		switch scope {
		case domain.RuleScopeOrg:
			scopeRefID = pending.OrgID
		case domain.RuleScopeUser:
			scopeRefID = pending.UserID
		case domain.RuleScopeAgent:
			scopeRefID = pending.AgentID
		}

		approved, _, err := s.store.ApproveRequestWithScopedRule(ctx, requestID, adminID, scope, scopeRefID, store.OrgRuleOptions{
			ExpiresAt: body.ExpiresAt,
		}, store.AuditInput{
			EgressRequestID: requestID,
			EventType:       rememberEventType(scope),
			ActorID:         adminID,
			Metadata: map[string]any{
				"scope": scope,
			},
		})
		return approved, err
	}

	return s.store.ApproveRequestOnce(ctx, requestID, adminID, store.AuditInput{
		EgressRequestID: requestID,
		EventType:       "egress_approved_once",
		ActorID:         adminID,
		Metadata: map[string]any{
			"scope": body.Scope,
		},
	})
}

func rememberEventType(scope domain.RuleScope) string {
	switch scope {
	case domain.RuleScopeAgent:
		return "egress_approved_agent_rule"
	case domain.RuleScopeUser:
		return "egress_approved_user_rule"
	default:
		return "egress_approved_org_rule"
	}
}

func (s *EgressService) Deny(ctx context.Context, requestID, adminID, feedback string) (domain.EgressRequest, error) {
	metadata := map[string]any{}
	if feedback != "" {
		metadata["feedback"] = feedback
	}

	return s.store.DenyRequest(ctx, requestID, adminID, feedback, store.AuditInput{
		EgressRequestID: requestID,
		EventType:       "egress_denied",
		ActorID:         adminID,
		Metadata:        metadata,
	})
}

func (s *EgressService) RevokeRule(ctx context.Context, ruleID, adminID string) error {
	return s.store.DeletePolicyRule(ctx, ruleID, store.AuditInput{
		EventType: "policy_rule_revoked",
		ActorID:   adminID,
		Metadata: map[string]any{
			"rule_id": ruleID,
		},
	})
}

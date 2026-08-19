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
		if scope != domain.RuleScopeOrg {
			return domain.EgressRequest{}, domain.ErrRememberScopeNotSupported{Scope: scope}
		}

		pending, err := s.store.GetEgressRequest(ctx, requestID)
		if err != nil {
			return domain.EgressRequest{}, err
		}
		if pending.Method == "CONNECT" {
			return domain.EgressRequest{}, domain.ErrRememberCONNECTNotAllowed{Host: pending.Host}
		}
		if err := validateExpiresAt(body.ExpiresAt); err != nil {
			return domain.EgressRequest{}, err
		}

		approved, _, err := s.store.ApproveRequestWithOrgRule(ctx, requestID, adminID, store.OrgRuleOptions{
			ExpiresAt: body.ExpiresAt,
		}, store.AuditInput{
			EgressRequestID: requestID,
			EventType:       "egress_approved_org_rule",
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

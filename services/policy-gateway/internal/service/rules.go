package service

import (
	"context"
	"strings"
	"time"

	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/store"
)

func normalizeRuleFields(body *domain.CreatePolicyRuleBody) {
	body.Host = strings.TrimSpace(strings.ToLower(body.Host))
	body.Method = strings.TrimSpace(strings.ToUpper(body.Method))
	body.PathPrefix = strings.TrimSpace(body.PathPrefix)
	body.ScopeRefID = strings.TrimSpace(body.ScopeRefID)

	if body.Port == 0 {
		body.Port = 443
	}
	if body.Method == "" {
		body.Method = "*"
	}
	if body.PathPrefix == "" {
		body.PathPrefix = "/"
	}
}

func validateExpiresAt(expiresAt *time.Time) error {
	if expiresAt == nil {
		return nil
	}
	if !expiresAt.After(time.Now()) {
		return domain.ErrExpiresAtInPast{}
	}
	return nil
}

func validatePersistentAllowMethod(method string) error {
	if method == "CONNECT" {
		return domain.ErrRuleCONNECTNotAllowed{Method: method}
	}
	return nil
}

func validateScopeRef(orgID string, scope domain.RuleScope, scopeRefID string) error {
	switch scope {
	case domain.RuleScopeOrg:
		if scopeRefID != orgID {
			return domain.ErrInvalidScopeRef{Scope: scope, ScopeRefID: scopeRefID, OrgID: orgID}
		}
	case domain.RuleScopeUser, domain.RuleScopeAgent:
		if scopeRefID == "" {
			return domain.ErrInvalidScopeRef{Scope: scope, ScopeRefID: scopeRefID, OrgID: orgID}
		}
	default:
		return domain.InvalidEnumError{Field: "scope", Value: string(scope)}
	}
	return nil
}

func (s *EgressService) CreateRule(ctx context.Context, orgID, adminID string, body domain.CreatePolicyRuleBody) (domain.PolicyRule, error) {
	if body.Scope == domain.RuleScopeOrg && body.ScopeRefID == "" {
		body.ScopeRefID = orgID
	}
	if body.Scope == "" {
		body.Scope = domain.RuleScopeOrg
	}
	normalizeRuleFields(&body)

	if body.Host == "" {
		return domain.PolicyRule{}, domain.InvalidEnumError{Field: "host", Value: ""}
	}
	if body.Effect != domain.RuleEffectAllow && body.Effect != domain.RuleEffectDeny {
		return domain.PolicyRule{}, domain.InvalidEnumError{Field: "effect", Value: string(body.Effect)}
	}
	if body.Effect == domain.RuleEffectAllow {
		if err := validatePersistentAllowMethod(body.Method); err != nil {
			return domain.PolicyRule{}, err
		}
	}
	if err := validateExpiresAt(body.ExpiresAt); err != nil {
		return domain.PolicyRule{}, err
	}
	if err := validateScopeRef(orgID, body.Scope, body.ScopeRefID); err != nil {
		return domain.PolicyRule{}, err
	}

	return s.store.CreatePolicyRule(ctx, store.CreatePolicyRuleInput{
		OrgID:      orgID,
		Scope:      body.Scope,
		ScopeRefID: body.ScopeRefID,
		Effect:     body.Effect,
		Host:       body.Host,
		Port:       body.Port,
		Method:     body.Method,
		PathPrefix: body.PathPrefix,
		ExpiresAt:  body.ExpiresAt,
		CreatedBy:  adminID,
	}, store.AuditInput{
		EventType: "policy_rule_created",
		ActorID:   adminID,
		Metadata: map[string]any{
			"scope": body.Scope,
		},
	})
}

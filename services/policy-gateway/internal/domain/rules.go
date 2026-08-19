package domain

import (
	"fmt"
	"time"
)

type CreatePolicyRuleBody struct {
	Scope      RuleScope  `json:"scope"`
	ScopeRefID string     `json:"scope_ref_id"`
	Effect     RuleEffect `json:"effect"`
	Host       string     `json:"host"`
	Port       int        `json:"port"`
	Method     string     `json:"method"`
	PathPrefix string     `json:"path_prefix"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

type ErrRuleCONNECTNotAllowed struct {
	Method string
}

func (e ErrRuleCONNECTNotAllowed) Error() string {
	return "CONNECT method is not allowed in persistent allow rules (method=" + e.Method + ")"
}

type ErrExpiresAtInPast struct{}

func (e ErrExpiresAtInPast) Error() string {
	return "expires_at must be in the future"
}

type ErrRuleAlreadyExists struct {
	Host       string
	Port       int
	Method     string
	PathPrefix string
}

func (e ErrRuleAlreadyExists) Error() string {
	return fmt.Sprintf(
		"policy rule already exists for %s %s:%d%s",
		e.Method, e.Host, e.Port, e.PathPrefix,
	)
}

type ErrInvalidScopeRef struct {
	Scope      RuleScope
	ScopeRefID string
	OrgID      string
}

func (e ErrInvalidScopeRef) Error() string {
	return "invalid scope_ref_id for scope=" + string(e.Scope)
}

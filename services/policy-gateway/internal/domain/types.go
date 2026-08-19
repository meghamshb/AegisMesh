package domain

import "time"

type RequestStatus string

const (
	RequestStatusPending      RequestStatus = "pending"
	RequestStatusApproved     RequestStatus = "approved"
	RequestStatusDenied       RequestStatus = "denied"
	RequestStatusAutoApproved RequestStatus = "auto_approved"
	RequestStatusExpired      RequestStatus = "expired"
)

type RuleEffect string

const (
	RuleEffectAllow RuleEffect = "allow"
	RuleEffectDeny  RuleEffect = "deny"
)

type RuleScope string

const (
	RuleScopeOrg   RuleScope = "org"
	RuleScopeUser  RuleScope = "user"
	RuleScopeAgent RuleScope = "agent"
)

type EgressRequest struct {
	ID           string        `json:"id"`
	AgentID      string        `json:"agent_id"`
	UserID       string        `json:"user_id"`
	OrgID        string        `json:"org_id"`
	Method       string        `json:"method"`
	Host         string        `json:"host"`
	Port         int           `json:"port"`
	Path         string        `json:"path"`
	Scheme       string        `json:"scheme"`
	Status       RequestStatus `json:"status"`
	RuleID       *string       `json:"rule_id,omitempty"`
	RequestedAt  time.Time     `json:"requested_at"`
	DecidedAt    *time.Time    `json:"decided_at,omitempty"`
	DecidedBy    *string       `json:"decided_by,omitempty"`
	ErrorMessage *string       `json:"error_message,omitempty"`
}

type PolicyRule struct {
	ID         string     `json:"id"`
	OrgID      string     `json:"org_id"`
	Scope      RuleScope  `json:"scope"`
	ScopeRefID string     `json:"scope_ref_id"`
	Effect     RuleEffect `json:"effect"`
	Host       string     `json:"host"`
	Port       int        `json:"port"`
	Method     string     `json:"method"`
	PathPrefix string     `json:"path_prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	CreatedBy  string     `json:"created_by"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

type HealthStatus struct {
	Status   string            `json:"status"`
	Service  string            `json:"service"`
	Version  string            `json:"version"`
	Checks   map[string]string `json:"checks"`
}

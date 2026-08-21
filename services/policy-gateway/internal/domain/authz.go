package domain

// Principal is the authenticated caller of a control-plane (human-facing
// admin API) request. It is deliberately distinct from a data-plane
// RequestIdentity (an authenticated agent's proxy traffic): a Principal
// manages the system, a RequestIdentity is what's being managed.
type Principal struct {
	ActorID string
	OrgID   string
	Role    string
}

const (
	RoleAdmin    = "admin"
	RoleApprover = "approver"
	RoleMember   = "member"
)

// The permission checks below encode the target role model from the
// handoff spec (member / approver / admin). Until Phase 5.13 wires up
// real per-caller authentication, every control-plane request is
// authenticated as a single admin-token principal, so these currently
// always return true for that principal - but the call sites already
// route through here rather than inlining role logic, so swapping in
// real multi-principal auth later doesn't require touching handlers.

func (p Principal) CanManageUsers() bool {
	return p.Role == RoleAdmin
}

func (p Principal) CanManageAgent(ownerUserID string) bool {
	return p.Role == RoleAdmin || p.Role == RoleApprover || p.ActorID == ownerUserID
}

func (p Principal) CanCreateRule(scope RuleScope) bool {
	switch scope {
	case RuleScopeOrg:
		return p.Role == RoleAdmin
	case RuleScopeUser:
		return p.Role == RoleAdmin || p.Role == RoleApprover
	case RuleScopeAgent:
		return true // agent owners may always create agent-scoped rules for their own agent
	default:
		return false
	}
}

func (p Principal) CanRevokeRule() bool {
	return p.Role == RoleAdmin
}

func (p Principal) CanApproveRequest(requestUserID string) bool {
	return p.Role == RoleAdmin || p.Role == RoleApprover || p.ActorID == requestUserID
}

func (p Principal) CanViewRequest(requestUserID string) bool {
	return p.Role == RoleAdmin || p.Role == RoleApprover || p.ActorID == requestUserID
}

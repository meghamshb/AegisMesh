package policy

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
)

// RuleSource supplies the persistent allow/deny rules that apply to one
// request. It is the seam that lets a distributed gateway decide policy from
// its locally cached snapshot instead of querying Postgres directly.
//
// It covers *only* the rule set. Request-history state - standing denies and
// approve-once grants - is deliberately not part of this interface, because it
// is per-request mutable state rather than policy, and stays in the store.
type RuleSource interface {
	MatchRules(ctx context.Context, in store.MatchRulesInput) ([]domain.PolicyRule, error)
}

// ErrPolicyUnavailable means no trustworthy rule set could be obtained - the
// snapshot never loaded, or went stale past its ceiling. Callers must fail
// closed: evaluating against an unknown rule set is worse than refusing.
var ErrPolicyUnavailable = errors.New("policy snapshot unavailable or stale; failing closed")

// storeRuleSource is the original behavior: match rules with a SQL query.
// Used by CLEARANCE_MODE=all and by any gateway not configured against a
// control plane, so single-process deployments are unchanged.
type storeRuleSource struct {
	store store.Store
}

func (s storeRuleSource) MatchRules(ctx context.Context, in store.MatchRulesInput) ([]domain.PolicyRule, error) {
	return s.store.MatchRules(ctx, in)
}

// SnapshotProvider is the read side of policycache.Cache. Declared here (not
// imported) so the policy package does not depend on the cache implementation.
type SnapshotProvider interface {
	Rules() ([]domain.PolicyRule, bool)
}

// snapshotRuleSource evaluates against the locally cached policy snapshot.
//
// The filtering below must stay behaviourally identical to the SQL in
// Postgres.MatchRules - the same request must get the same verdict whether it
// is decided centrally or at the edge. matchesRule is the single place that
// predicate is expressed in Go, and policy_parity_test.go pins the two
// implementations against each other.
type snapshotRuleSource struct {
	snapshots SnapshotProvider
}

func (s snapshotRuleSource) MatchRules(_ context.Context, in store.MatchRulesInput) ([]domain.PolicyRule, error) {
	rules, ok := s.snapshots.Rules()
	if !ok {
		return nil, ErrPolicyUnavailable
	}

	now := time.Now()
	matched := make([]domain.PolicyRule, 0, len(rules))
	for _, rule := range rules {
		if matchesRule(rule, in, now) {
			matched = append(matched, rule)
		}
	}

	// Postgres orders by created_at ASC; mostSpecificAllow and the deny scan
	// both depend on a stable order, so preserve it here too. Snapshot rules
	// already arrive in created_at order from ListRulesForOrgSnapshot, so this
	// is an insertion-order-preserving filter rather than a re-sort.
	return matched, nil
}

// matchesRule mirrors, clause for clause, the WHERE in Postgres.MatchRules.
func matchesRule(rule domain.PolicyRule, in store.MatchRulesInput, now time.Time) bool {
	// org_id = $1
	if rule.OrgID != in.OrgID {
		return false
	}
	// host = $2 AND port = $3
	if rule.Host != in.Host || rule.Port != in.Port {
		return false
	}
	// (method = '*' OR method = $4)
	if rule.Method != "*" && rule.Method != in.Method {
		return false
	}
	// starts_with($5, path_prefix) AND (length($5) = length(path_prefix)
	//   OR substring($5 from length(path_prefix)+1 for 1) = '/')
	if !pathWithinPrefix(in.Path, rule.PathPrefix) {
		return false
	}
	// (expires_at IS NULL OR expires_at > NOW())
	//
	// Re-checked locally even though the snapshot excludes expired rules at
	// fetch time: a cached snapshot can outlive a rule's expiry, and an
	// expired allow must stop applying without waiting for the next refresh.
	if rule.ExpiresAt != nil && !rule.ExpiresAt.After(now) {
		return false
	}
	// scope/scope_ref_id triple
	switch rule.Scope {
	case domain.RuleScopeOrg:
		return rule.ScopeRefID == in.OrgID
	case domain.RuleScopeUser:
		return rule.ScopeRefID == in.UserID
	case domain.RuleScopeAgent:
		return rule.ScopeRefID == in.AgentID
	default:
		return false
	}
}

// pathWithinPrefix reproduces the SQL path-boundary check: the request path
// must start with the prefix, and the prefix must end on a segment boundary so
// that "/foobar" is not matched by a rule for "/foo".
//
// The trailing-slash clause matters more than it looks. Without it a prefix of
// "/" - which is the default for a rule created without an explicit
// path_prefix, i.e. "allow this host" - would match only the literal path "/",
// because there is no separator character after the prefix span to inspect.
// A host-wide allow rule that silently authorizes nothing is worse than no
// rule at all, so a prefix already ending in "/" is treated as sitting on a
// boundary by construction. The SQL in Postgres.MatchRules carries the same
// clause.
func pathWithinPrefix(path, prefix string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	if len(path) == len(prefix) {
		return true
	}
	if strings.HasSuffix(prefix, "/") {
		return true
	}
	// substring(path from len(prefix)+1 for 1) = '/'
	return path[len(prefix)] == '/'
}

//go:build integration

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/policy"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
)

// Phase 5.10 lets a distributed gateway decide policy from a locally cached
// snapshot instead of querying Postgres. That is only safe if the Go matcher
// and the SQL predicate agree exactly - otherwise the same request gets one
// verdict centrally and a different one at the edge, which is the worst
// possible failure mode for a policy gateway.
//
// This test seeds a rule set in Postgres, then runs a matrix of request tuples
// through *both* implementations and asserts identical results.

// snapshotProvider adapts a fixed rule set to policy.SnapshotProvider.
type snapshotProvider struct{ rules []domain.PolicyRule }

func (s snapshotProvider) Rules() ([]domain.PolicyRule, bool) { return s.rules, true }

func TestSnapshotMatcherMatchesSQLExactly(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()

	host := "parity-test.example"
	future := time.Now().Add(2 * time.Hour)
	past := time.Now().Add(-2 * time.Hour)

	// A rule set that exercises every clause: scope variants, wildcard vs
	// explicit method, nested and root path prefixes, expiry both ways.
	seed := []store.CreatePolicyRuleInput{
		{Scope: domain.RuleScopeOrg, ScopeRefID: seededOrgID, Effect: domain.RuleEffectAllow, Host: host, Port: 443, Method: "*", PathPrefix: "/"},
		{Scope: domain.RuleScopeOrg, ScopeRefID: seededOrgID, Effect: domain.RuleEffectDeny, Host: host, Port: 443, Method: "*", PathPrefix: "/admin"},
		{Scope: domain.RuleScopeUser, ScopeRefID: seededUserID, Effect: domain.RuleEffectAllow, Host: host, Port: 443, Method: "POST", PathPrefix: "/api"},
		{Scope: domain.RuleScopeAgent, ScopeRefID: seededAgentID, Effect: domain.RuleEffectAllow, Host: host, Port: 8443, Method: "GET", PathPrefix: "/agent-only"},
		{Scope: domain.RuleScopeOrg, ScopeRefID: seededOrgID, Effect: domain.RuleEffectAllow, Host: host, Port: 443, Method: "*", PathPrefix: "/expired", ExpiresAt: &past},
		{Scope: domain.RuleScopeOrg, ScopeRefID: seededOrgID, Effect: domain.RuleEffectAllow, Host: host, Port: 443, Method: "*", PathPrefix: "/future", ExpiresAt: &future},
	}
	for i := range seed {
		seed[i].OrgID = seededOrgID
		seed[i].CreatedBy = seededAdminID
		if _, err := pg.CreatePolicyRule(ctx, seed[i], store.AuditInput{
			OrgID: seededOrgID, EventType: "policy_rule_created", ActorID: seededAdminID,
		}); err != nil {
			// Re-running the suite against the same database is expected;
			// a duplicate simply means the rule is already seeded.
			var exists domain.ErrRuleAlreadyExists
			if !asRuleExists(err, &exists) {
				t.Fatalf("seed rule %d: %v", i, err)
			}
		}
	}

	// The snapshot the gateway would be holding.
	snapshotRules, err := pg.ListRulesForOrgSnapshot(ctx, seededOrgID)
	if err != nil {
		t.Fatalf("ListRulesForOrgSnapshot: %v", err)
	}
	engineSource := policy.NewSnapshotRuleEngine(snapshotProvider{rules: snapshotRules}, pg)

	cases := []store.MatchRulesInput{
		{Host: host, Port: 443, Method: "GET", Path: "/"},
		{Host: host, Port: 443, Method: "GET", Path: "/anything"},
		{Host: host, Port: 443, Method: "GET", Path: "/admin"},
		{Host: host, Port: 443, Method: "GET", Path: "/admin/settings"},
		{Host: host, Port: 443, Method: "GET", Path: "/adminsettings"}, // boundary: must NOT hit /admin
		{Host: host, Port: 443, Method: "POST", Path: "/api"},
		{Host: host, Port: 443, Method: "POST", Path: "/api/v1/things"},
		{Host: host, Port: 443, Method: "GET", Path: "/api"},     // method mismatch on the user rule
		{Host: host, Port: 443, Method: "GET", Path: "/apikeys"}, // boundary: must NOT hit /api
		{Host: host, Port: 8443, Method: "GET", Path: "/agent-only/x"},
		{Host: host, Port: 443, Method: "GET", Path: "/agent-only/x"}, // wrong port for the agent rule
		{Host: host, Port: 443, Method: "GET", Path: "/expired"},
		{Host: host, Port: 443, Method: "GET", Path: "/future"},
		{Host: "unrelated.example", Port: 443, Method: "GET", Path: "/"},
	}

	for _, base := range cases {
		in := base
		in.OrgID = seededOrgID
		in.UserID = seededUserID
		in.AgentID = seededAgentID

		t.Run(in.Method+" "+in.Host+in.Path, func(t *testing.T) {
			fromSQL, err := pg.MatchRules(ctx, in)
			if err != nil {
				t.Fatalf("SQL MatchRules: %v", err)
			}

			req := policy.Request{
				OrgID: in.OrgID, UserID: in.UserID, AgentID: in.AgentID,
				Host: in.Host, Port: in.Port, Method: in.Method, Path: in.Path,
			}
			// Compare the rule sets themselves, via the same source the
			// engine uses, rather than only the final decision - a decision
			// can coincide while the underlying match sets differ.
			fromSnapshot, err := matchViaSnapshot(snapshotRules, in)
			if err != nil {
				t.Fatalf("snapshot match: %v", err)
			}

			if !sameRuleIDs(fromSQL, fromSnapshot) {
				t.Fatalf("match set differs for %s %s%s:\n  SQL      = %v\n  snapshot = %v",
					in.Method, in.Host, in.Path, idsOf(fromSQL), idsOf(fromSnapshot))
			}

			// And the end-to-end verdicts must agree too.
			sqlEval, err := policy.NewRuleEngine(pg).Evaluate(ctx, req)
			if err != nil {
				t.Fatalf("SQL engine evaluate: %v", err)
			}
			snapEval, err := engineSource.Evaluate(ctx, req)
			if err != nil {
				t.Fatalf("snapshot engine evaluate: %v", err)
			}
			if sqlEval.Decision != snapEval.Decision {
				t.Fatalf("decision differs for %s %s%s: SQL=%s snapshot=%s",
					in.Method, in.Host, in.Path, sqlEval.Decision, snapEval.Decision)
			}
		})
	}
}

// matchViaSnapshot runs the snapshot matcher through the exported engine seam.
func matchViaSnapshot(rules []domain.PolicyRule, in store.MatchRulesInput) ([]domain.PolicyRule, error) {
	return policy.MatchSnapshotRulesForTest(rules, in)
}

func sameRuleIDs(a, b []domain.PolicyRule) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, r := range a {
		seen[r.ID]++
	}
	for _, r := range b {
		seen[r.ID]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

func idsOf(rules []domain.PolicyRule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, string(r.Scope)+":"+r.PathPrefix+":"+string(r.Effect))
	}
	return out
}

func asRuleExists(err error, target *domain.ErrRuleAlreadyExists) bool {
	for err != nil {
		if e, ok := err.(domain.ErrRuleAlreadyExists); ok {
			*target = e
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

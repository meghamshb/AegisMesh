package policy

import (
	"context"
	"testing"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
)

// The snapshot matcher has to agree with the SQL in Postgres.MatchRules
// clause for clause, or a request gets one verdict centrally and a different
// one at the edge. These cases pin each clause individually; the end-to-end
// parity check against a real database lives in
// internal/store/policy_parity_integration_test.go.

const (
	testOrg   = "org-1"
	testUser  = "user-1"
	testAgent = "agent-1"
)

func baseInput() store.MatchRulesInput {
	return store.MatchRulesInput{
		OrgID:   testOrg,
		UserID:  testUser,
		AgentID: testAgent,
		Host:    "example.com",
		Port:    443,
		Method:  "GET",
		Path:    "/api/data",
	}
}

func baseRule() domain.PolicyRule {
	return domain.PolicyRule{
		ID:         "rule-1",
		OrgID:      testOrg,
		Scope:      domain.RuleScopeOrg,
		ScopeRefID: testOrg,
		Effect:     domain.RuleEffectAllow,
		Host:       "example.com",
		Port:       443,
		Method:     "*",
		PathPrefix: "/api",
	}
}

func TestMatchesRuleClauses(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	tests := []struct {
		name  string
		muts  func(*domain.PolicyRule, *store.MatchRulesInput)
		want  bool
		claus string
	}{
		{name: "baseline matches", muts: func(*domain.PolicyRule, *store.MatchRulesInput) {}, want: true},

		{
			name:  "different org does not match",
			claus: "org_id = $1",
			muts:  func(r *domain.PolicyRule, _ *store.MatchRulesInput) { r.OrgID = "org-2" },
			want:  false,
		},
		{
			name:  "different host does not match",
			claus: "host = $2",
			muts:  func(r *domain.PolicyRule, _ *store.MatchRulesInput) { r.Host = "other.com" },
			want:  false,
		},
		{
			name:  "different port does not match",
			claus: "port = $3",
			muts:  func(r *domain.PolicyRule, _ *store.MatchRulesInput) { r.Port = 8443 },
			want:  false,
		},
		{
			name:  "wildcard method matches any method",
			claus: "method = '*'",
			muts:  func(r *domain.PolicyRule, in *store.MatchRulesInput) { r.Method = "*"; in.Method = "DELETE" },
			want:  true,
		},
		{
			name:  "exact method matches",
			claus: "method = $4",
			muts:  func(r *domain.PolicyRule, in *store.MatchRulesInput) { r.Method = "POST"; in.Method = "POST" },
			want:  true,
		},
		{
			name:  "mismatched explicit method does not match",
			claus: "method = $4",
			muts:  func(r *domain.PolicyRule, in *store.MatchRulesInput) { r.Method = "POST"; in.Method = "GET" },
			want:  false,
		},

		// Path boundary: the clause that stops /foo from authorizing /foobar.
		{
			name:  "exact path equals prefix",
			claus: "length($5) = length(path_prefix)",
			muts:  func(r *domain.PolicyRule, in *store.MatchRulesInput) { r.PathPrefix = "/api"; in.Path = "/api" },
			want:  true,
		},
		{
			name:  "path continues on a segment boundary",
			claus: "substring(...) = '/'",
			muts:  func(r *domain.PolicyRule, in *store.MatchRulesInput) { r.PathPrefix = "/api"; in.Path = "/api/data" },
			want:  true,
		},
		{
			name:  "prefix must end on a segment boundary",
			claus: "substring(...) = '/'",
			muts:  func(r *domain.PolicyRule, in *store.MatchRulesInput) { r.PathPrefix = "/api"; in.Path = "/apikeys" },
			want:  false,
		},
		{
			name:  "unrelated path does not match",
			claus: "starts_with($5, path_prefix)",
			muts:  func(r *domain.PolicyRule, in *store.MatchRulesInput) { r.PathPrefix = "/admin"; in.Path = "/api" },
			want:  false,
		},

		{
			name:  "unexpired rule matches",
			claus: "expires_at > NOW()",
			muts:  func(r *domain.PolicyRule, _ *store.MatchRulesInput) { r.ExpiresAt = &future },
			want:  true,
		},
		{
			name:  "expired rule does not match",
			claus: "expires_at > NOW()",
			muts:  func(r *domain.PolicyRule, _ *store.MatchRulesInput) { r.ExpiresAt = &past },
			want:  false,
		},

		{
			name:  "org scope requires scope_ref_id = org",
			claus: "scope = 'org' AND scope_ref_id = $1",
			muts: func(r *domain.PolicyRule, _ *store.MatchRulesInput) {
				r.Scope = domain.RuleScopeOrg
				r.ScopeRefID = "some-other-id"
			},
			want: false,
		},
		{
			name:  "user scope matches the requesting user",
			claus: "scope = 'user' AND scope_ref_id = $6",
			muts: func(r *domain.PolicyRule, _ *store.MatchRulesInput) {
				r.Scope = domain.RuleScopeUser
				r.ScopeRefID = testUser
			},
			want: true,
		},
		{
			name:  "user scope for a different user does not match",
			claus: "scope = 'user' AND scope_ref_id = $6",
			muts: func(r *domain.PolicyRule, _ *store.MatchRulesInput) {
				r.Scope = domain.RuleScopeUser
				r.ScopeRefID = "user-2"
			},
			want: false,
		},
		{
			name:  "agent scope matches the requesting agent",
			claus: "scope = 'agent' AND scope_ref_id = $7",
			muts: func(r *domain.PolicyRule, _ *store.MatchRulesInput) {
				r.Scope = domain.RuleScopeAgent
				r.ScopeRefID = testAgent
			},
			want: true,
		},
		{
			name:  "agent scope for a different agent does not match",
			claus: "scope = 'agent' AND scope_ref_id = $7",
			muts: func(r *domain.PolicyRule, _ *store.MatchRulesInput) {
				r.Scope = domain.RuleScopeAgent
				r.ScopeRefID = "agent-2"
			},
			want: false,
		},
		{
			name:  "unknown scope never matches",
			claus: "scope triple",
			muts:  func(r *domain.PolicyRule, _ *store.MatchRulesInput) { r.Scope = domain.RuleScope("bogus") },
			want:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rule := baseRule()
			in := baseInput()
			tc.muts(&rule, &in)

			if got := matchesRule(rule, in, now); got != tc.want {
				t.Fatalf("matchesRule = %v, want %v (SQL clause: %s)", got, tc.want, tc.claus)
			}
		})
	}
}

// A root prefix "/" must authorize every path under it. This is the edge case
// the SQL boundary check gets subtly wrong for a bare "/" and which earlier
// phases worked around by avoiding root-prefix rules in tests, so pin the Go
// behavior explicitly.
func TestRootPrefixMatchesEverything(t *testing.T) {
	now := time.Now()
	for _, path := range []string{"/", "/a", "/a/b", "/fleet-test"} {
		rule := baseRule()
		rule.PathPrefix = "/"
		in := baseInput()
		in.Path = path

		if !matchesRule(rule, in, now) {
			t.Fatalf("root prefix should match path %q", path)
		}
	}
}

type stubSnapshots struct {
	rules []domain.PolicyRule
	ok    bool
}

func (s stubSnapshots) Rules() ([]domain.PolicyRule, bool) { return s.rules, s.ok }

func TestSnapshotSourceFailsClosedWhenUnavailable(t *testing.T) {
	src := snapshotRuleSource{snapshots: stubSnapshots{ok: false}}

	_, err := src.MatchRules(context.Background(), baseInput())
	if err != ErrPolicyUnavailable {
		t.Fatalf("err = %v, want ErrPolicyUnavailable", err)
	}
}

func TestSnapshotSourcePreservesOrder(t *testing.T) {
	first := baseRule()
	first.ID = "first"
	second := baseRule()
	second.ID = "second"
	noise := baseRule()
	noise.ID = "noise"
	noise.Host = "unrelated.com"

	src := snapshotRuleSource{snapshots: stubSnapshots{rules: []domain.PolicyRule{first, noise, second}, ok: true}}

	got, err := src.MatchRules(context.Background(), baseInput())
	if err != nil {
		t.Fatalf("MatchRules: %v", err)
	}
	if len(got) != 2 || got[0].ID != "first" || got[1].ID != "second" {
		t.Fatalf("expected [first second] in order, got %v", ruleIDs(got))
	}
}

func ruleIDs(rules []domain.PolicyRule) []string {
	ids := make([]string, 0, len(rules))
	for _, r := range rules {
		ids = append(ids, r.ID)
	}
	return ids
}

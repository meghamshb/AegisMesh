//go:build integration

package store_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
)

func integrationDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		dsn = "postgres://hermes:hermes@localhost:5432/hermes_policy?sslmode=disable"
	}
	return dsn
}

func newTestPostgres(t *testing.T) *store.Postgres {
	t.Helper()
	ctx := context.Background()
	pg, err := store.NewPostgres(ctx, integrationDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable for integration test: %v", err)
	}
	t.Cleanup(pg.Close)
	return pg
}

func TestApproveRequestWithOrgRuleIsAtomic(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()

	_, err := pg.CreateEgressRequest(ctx, store.CreateEgressRequestInput{
		AgentID: "11111111-1111-1111-1111-111111111020",
		UserID:  "11111111-1111-1111-1111-111111111001",
		OrgID:   "11111111-1111-1111-1111-111111111010",
		Method:  "GET",
		Host:    "integration-test.example",
		Port:    443,
		Path:    "/phase35",
		Scheme:  "https",
		Status:  domain.RequestStatusPending,
	})
	if err != nil {
		t.Fatalf("CreateEgressRequest: %v", err)
	}

	requests, err := pg.ListRequests(ctx, store.ListRequestsInput{
		Status: ptrStatus(domain.RequestStatusPending),
		Host:   "integration-test.example",
		Limit:  1,
	})
	if err != nil || len(requests) == 0 {
		t.Fatalf("pending request not found: %v", err)
	}

	expires := time.Now().Add(24 * time.Hour)
	approved, rule, err := pg.ApproveRequestWithOrgRule(ctx, requests[0].ID, "11111111-1111-1111-1111-111111111002", store.OrgRuleOptions{
		ExpiresAt: &expires,
	}, store.AuditInput{
		EgressRequestID: requests[0].ID,
		EventType:       "egress_approved_org_rule",
		ActorID:         "11111111-1111-1111-1111-111111111002",
		Metadata:        map[string]any{},
	})
	if err != nil {
		t.Fatalf("ApproveRequestWithOrgRule: %v", err)
	}
	if approved.Status != domain.RequestStatusApproved {
		t.Fatalf("status = %q, want approved", approved.Status)
	}
	if rule.ExpiresAt == nil {
		t.Fatal("expected expires_at on org rule")
	}

	matched, err := pg.MatchRules(ctx, store.MatchRulesInput{
		OrgID:   "11111111-1111-1111-1111-111111111010",
		UserID:  "11111111-1111-1111-1111-111111111001",
		AgentID: "11111111-1111-1111-1111-111111111020",
		Host:    "integration-test.example",
		Port:    443,
		Method:  "GET",
		Path:    "/phase35/extra",
	})
	if err != nil {
		t.Fatalf("MatchRules: %v", err)
	}
	if len(matched) == 0 {
		t.Fatal("expected org rule to match")
	}

	if err := pg.DeletePolicyRule(ctx, rule.ID, store.AuditInput{
		EventType: "policy_rule_revoked",
		ActorID:   "11111111-1111-1111-1111-111111111002",
		Metadata:  map[string]any{"rule_id": rule.ID},
	}); err != nil {
		t.Fatalf("DeletePolicyRule cleanup: %v", err)
	}
}

func TestCreatePolicyRuleConflict(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()

	in := store.CreatePolicyRuleInput{
		OrgID:      "11111111-1111-1111-1111-111111111010",
		Scope:      domain.RuleScopeOrg,
		ScopeRefID: "11111111-1111-1111-1111-111111111010",
		Effect:     domain.RuleEffectAllow,
		Host:       "manual-rule.example",
		Port:       443,
		Method:     "GET",
		PathPrefix: "/health",
		CreatedBy:  "11111111-1111-1111-1111-111111111002",
	}

	_, err := pg.CreatePolicyRule(ctx, in, store.AuditInput{
		EventType: "policy_rule_created",
		ActorID:   in.CreatedBy,
		Metadata:  map[string]any{},
	})
	if err != nil {
		t.Fatalf("first CreatePolicyRule: %v", err)
	}

	_, err = pg.CreatePolicyRule(ctx, in, store.AuditInput{
		EventType: "policy_rule_created",
		ActorID:   in.CreatedBy,
		Metadata:  map[string]any{},
	})
	if err == nil {
		t.Fatal("expected duplicate rule conflict")
	}
	var exists domain.ErrRuleAlreadyExists
	if !errors.As(err, &exists) {
		t.Fatalf("error = %v, want ErrRuleAlreadyExists", err)
	}

	rules, err := pg.ListRules(ctx)
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	for _, rule := range rules {
		if rule.Host == "manual-rule.example" {
			_ = pg.DeletePolicyRule(ctx, rule.ID, store.AuditInput{
				EventType: "policy_rule_revoked",
				ActorID:   in.CreatedBy,
				Metadata:  map[string]any{"rule_id": rule.ID},
			})
		}
	}
}

func TestExpiredRuleDoesNotMatch(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()

	past := time.Now().Add(-time.Minute)
	_, err := pg.CreatePolicyRule(ctx, store.CreatePolicyRuleInput{
		OrgID:      "11111111-1111-1111-1111-111111111010",
		Scope:      domain.RuleScopeOrg,
		ScopeRefID: "11111111-1111-1111-1111-111111111010",
		Effect:     domain.RuleEffectAllow,
		Host:       "expired-rule.example",
		Port:       443,
		Method:     "GET",
		PathPrefix: "/",
		ExpiresAt:  &past,
		CreatedBy:  "11111111-1111-1111-1111-111111111002",
	}, store.AuditInput{
		EventType: "policy_rule_created",
		ActorID:   "11111111-1111-1111-1111-111111111002",
	})
	if err != nil {
		t.Fatalf("CreatePolicyRule: %v", err)
	}

	matched, err := pg.MatchRules(ctx, store.MatchRulesInput{
		OrgID:   "11111111-1111-1111-1111-111111111010",
		UserID:  "11111111-1111-1111-1111-111111111001",
		AgentID: "11111111-1111-1111-1111-111111111020",
		Host:    "expired-rule.example",
		Port:    443,
		Method:  "GET",
		Path:    "/any",
	})
	if err != nil {
		t.Fatalf("MatchRules: %v", err)
	}
	if len(matched) != 0 {
		t.Fatalf("expected no matches for expired rule, got %d", len(matched))
	}
}

func ptrStatus(status domain.RequestStatus) *domain.RequestStatus {
	return &status
}

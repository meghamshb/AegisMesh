//go:build integration

package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/identity"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
)

// These tests assert tenancy at the SQL layer, against a real Postgres. The
// API-level equivalents in internal/api/crossorg_test.go run against an
// in-memory fake; these prove the actual queries carry the org predicate, so a
// handler passing the right org is not the only thing standing between two
// tenants.

const otherOrgSlug = "crossorg-test-org"

// setupOtherOrg creates a second organization with its own user and agent, and
// returns (orgID, userID, agentID). Rows are reused across runs.
func setupOtherOrg(t *testing.T, pg *store.Postgres) (string, string, string) {
	t.Helper()
	ctx := context.Background()

	orgID, err := pg.EnsureTestOrganization(ctx, otherOrgSlug, "Cross-Org Test Organization")
	if err != nil {
		t.Fatalf("create second organization: %v", err)
	}

	users, err := pg.ListUsers(ctx, store.ListUsersInput{OrgID: orgID, Limit: 1})
	if err != nil {
		t.Fatalf("ListUsers(other org): %v", err)
	}
	var userID string
	if len(users) > 0 {
		userID = users[0].ID
	} else {
		user, err := pg.CreateUser(ctx, store.CreateUserInput{
			OrgID:       orgID,
			DisplayName: "Other Org Admin",
			Role:        domain.RoleAdmin,
		})
		if err != nil {
			t.Fatalf("CreateUser(other org): %v", err)
		}
		userID = user.ID
	}

	agents, err := pg.ListAgents(ctx, store.ListAgentsInput{OrgID: orgID, Limit: 1})
	if err != nil {
		t.Fatalf("ListAgents(other org): %v", err)
	}
	var agentID string
	if len(agents) > 0 {
		agentID = agents[0].ID
	} else {
		agent, err := pg.RegisterAgent(ctx, store.RegisterAgentInput{
			OrgID:       orgID,
			OwnerUserID: userID,
			Name:        "other-org-agent",
		}, store.AuditInput{OrgID: orgID, EventType: "agent_registered", ActorID: userID})
		if err != nil {
			t.Fatalf("RegisterAgent(other org): %v", err)
		}
		agentID = agent.ID
	}

	return orgID, userID, agentID
}

func assertNotFound(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected ErrNotFound, got nil error (cross-tenant access succeeded)", what)
	}
	var notFound domain.ErrNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("%s: expected ErrNotFound, got %v", what, err)
	}
}

func TestGetUserIsOrgScoped(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()
	_, otherUserID, _ := setupOtherOrg(t, pg)

	_, err := pg.GetUser(ctx, seededOrgID, otherUserID)
	assertNotFound(t, err, "GetUser across orgs")
}

func TestGetAgentIsOrgScoped(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()
	_, _, otherAgentID := setupOtherOrg(t, pg)

	_, err := pg.GetAgent(ctx, seededOrgID, otherAgentID)
	assertNotFound(t, err, "GetAgent across orgs")
}

func TestUpdateUserIsOrgScoped(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()
	otherOrgID, otherUserID, _ := setupOtherOrg(t, pg)

	demoted := domain.RoleMember
	_, err := pg.UpdateUser(ctx, seededOrgID, otherUserID, store.UpdateUserInput{Role: &demoted})
	assertNotFound(t, err, "UpdateUser across orgs")

	// And confirm the victim row is genuinely untouched.
	victim, err := pg.GetUser(ctx, otherOrgID, otherUserID)
	if err != nil {
		t.Fatalf("GetUser(own org) after blocked update: %v", err)
	}
	if victim.Role != domain.RoleAdmin {
		t.Fatalf("victim user role = %q, want %q - cross-org update mutated the row", victim.Role, domain.RoleAdmin)
	}
}

func TestRevokeAgentIsOrgScoped(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()
	otherOrgID, _, otherAgentID := setupOtherOrg(t, pg)

	_, err := pg.RevokeAgent(ctx, seededOrgID, otherAgentID, store.AuditInput{
		OrgID: seededOrgID, EventType: "agent_revoked", ActorID: seededAdminID,
	})
	assertNotFound(t, err, "RevokeAgent across orgs")

	victim, err := pg.GetAgent(ctx, otherOrgID, otherAgentID)
	if err != nil {
		t.Fatalf("GetAgent(own org) after blocked revoke: %v", err)
	}
	if victim.Status != "active" {
		t.Fatalf("victim agent status = %q, want active - cross-org revoke took effect", victim.Status)
	}
}

// The highest-severity finding: rotation mints a live credential, so it must
// refuse an agent outside the caller's org before issuing anything.
func TestRotateAgentCredentialIsOrgScoped(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()
	_, _, otherAgentID := setupOtherOrg(t, pg)

	token, err := identity.GenerateAgentToken()
	if err != nil {
		t.Fatalf("GenerateAgentToken: %v", err)
	}

	_, err = pg.RotateAgentCredential(ctx, seededOrgID, otherAgentID, store.CreateAgentCredentialInput{
		OrgID:       seededOrgID,
		AgentID:     otherAgentID,
		TokenPrefix: identity.TokenDisplayPrefix(token),
		TokenHash:   identity.HashAgentToken(token),
		CreatedBy:   seededAdminID,
	}, store.AuditInput{OrgID: seededOrgID, EventType: "agent_credential_rotated", ActorID: seededAdminID})
	assertNotFound(t, err, "RotateAgentCredential across orgs")

	// The rejected rotation must not have persisted a usable credential.
	if _, err := pg.GetAgentCredentialByHash(ctx, identity.HashAgentToken(token)); err == nil {
		t.Fatal("cross-org rotation persisted a working credential")
	}
}

func TestCreateAgentCredentialIsOrgScoped(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()
	_, _, otherAgentID := setupOtherOrg(t, pg)

	token, err := identity.GenerateAgentToken()
	if err != nil {
		t.Fatalf("GenerateAgentToken: %v", err)
	}

	_, err = pg.CreateAgentCredential(ctx, store.CreateAgentCredentialInput{
		OrgID:       seededOrgID,
		AgentID:     otherAgentID,
		TokenPrefix: identity.TokenDisplayPrefix(token),
		TokenHash:   identity.HashAgentToken(token),
		CreatedBy:   seededAdminID,
	}, store.AuditInput{OrgID: seededOrgID, EventType: "agent_credential_created", ActorID: seededAdminID})
	assertNotFound(t, err, "CreateAgentCredential across orgs")
}

func TestRegisterAgentRejectsOwnerFromAnotherOrg(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()
	_, otherUserID, _ := setupOtherOrg(t, pg)

	_, err := pg.RegisterAgent(ctx, store.RegisterAgentInput{
		OrgID:       seededOrgID,
		OwnerUserID: otherUserID,
		Name:        "smuggled-agent",
	}, store.AuditInput{OrgID: seededOrgID, EventType: "agent_registered", ActorID: seededAdminID})
	assertNotFound(t, err, "RegisterAgent with owner from another org")
}

func TestListsAreOrgScoped(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()
	otherOrgID, otherUserID, otherAgentID := setupOtherOrg(t, pg)

	users, err := pg.ListUsers(ctx, store.ListUsersInput{OrgID: seededOrgID, Limit: 200})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	for _, u := range users {
		if u.OrgID != seededOrgID {
			t.Fatalf("ListUsers returned a user from org %q", u.OrgID)
		}
		if u.ID == otherUserID {
			t.Fatal("ListUsers leaked the other org's user")
		}
	}

	agents, err := pg.ListAgents(ctx, store.ListAgentsInput{OrgID: seededOrgID, Limit: 200})
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	for _, a := range agents {
		if a.OrgID != seededOrgID {
			t.Fatalf("ListAgents returned an agent from org %q", a.OrgID)
		}
		if a.ID == otherAgentID {
			t.Fatal("ListAgents leaked the other org's agent")
		}
	}

	rules, err := pg.ListRules(ctx, store.ListRulesInput{OrgID: seededOrgID, Limit: 200})
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	for _, r := range rules {
		if r.OrgID != seededOrgID {
			t.Fatalf("ListRules returned a rule from org %q", r.OrgID)
		}
	}

	requests, err := pg.ListRequests(ctx, store.ListRequestsInput{OrgID: seededOrgID, Limit: 200})
	if err != nil {
		t.Fatalf("ListRequests: %v", err)
	}
	for _, r := range requests {
		if r.OrgID != seededOrgID {
			t.Fatalf("ListRequests returned a request from org %q", r.OrgID)
		}
	}

	// The other org must be able to see its own rows, proving the filter is a
	// filter and not a blanket exclusion.
	otherUsers, err := pg.ListUsers(ctx, store.ListUsersInput{OrgID: otherOrgID, Limit: 200})
	if err != nil {
		t.Fatalf("ListUsers(other org): %v", err)
	}
	if len(otherUsers) == 0 {
		t.Fatal("ListUsers(other org) returned nothing; the org filter excludes everything")
	}
}

func TestListAuditEventsIsOrgScoped(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()
	otherOrgID, otherUserID, _ := setupOtherOrg(t, pg)

	if err := pg.InsertAuditEvent(ctx, otherOrgID, "", "crossorg_probe_event", otherUserID, map[string]any{}); err != nil {
		t.Fatalf("InsertAuditEvent(other org): %v", err)
	}

	ours, err := pg.ListAuditEvents(ctx, store.ListAuditEventsInput{
		OrgID:     seededOrgID,
		EventType: "crossorg_probe_event",
		Limit:     200,
	})
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	if len(ours) != 0 {
		t.Fatalf("ListAuditEvents leaked %d event(s) from another org", len(ours))
	}

	theirs, err := pg.ListAuditEvents(ctx, store.ListAuditEventsInput{
		OrgID:     otherOrgID,
		EventType: "crossorg_probe_event",
		Limit:     200,
	})
	if err != nil {
		t.Fatalf("ListAuditEvents(other org): %v", err)
	}
	if len(theirs) == 0 {
		t.Fatal("ListAuditEvents(other org) did not return its own event")
	}
}

func TestDeletePolicyRuleIsOrgScoped(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()
	otherOrgID, otherUserID, _ := setupOtherOrg(t, pg)

	rule, err := pg.CreatePolicyRule(ctx, store.CreatePolicyRuleInput{
		OrgID:      otherOrgID,
		Scope:      domain.RuleScopeOrg,
		ScopeRefID: otherOrgID,
		Effect:     domain.RuleEffectAllow,
		Host:       "crossorg-delete-test.example",
		Port:       443,
		Method:     "*",
		PathPrefix: "/crossorg",
		CreatedBy:  otherUserID,
	}, store.AuditInput{OrgID: otherOrgID, EventType: "policy_rule_created", ActorID: otherUserID})
	if err != nil {
		t.Fatalf("CreatePolicyRule(other org): %v", err)
	}

	err = pg.DeletePolicyRule(ctx, seededOrgID, rule.ID, store.AuditInput{
		OrgID: seededOrgID, EventType: "policy_rule_revoked", ActorID: seededAdminID,
	})
	assertNotFound(t, err, "DeletePolicyRule across orgs")

	// Clean up as its rightful owner - which also proves the rule survived.
	if err := pg.DeletePolicyRule(ctx, otherOrgID, rule.ID, store.AuditInput{
		OrgID: otherOrgID, EventType: "policy_rule_revoked", ActorID: otherUserID,
	}); err != nil {
		t.Fatalf("rule was destroyed by the cross-org delete: %v", err)
	}
}

func TestGetGatewayIsOrgScoped(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()
	otherOrgID, _, _ := setupOtherOrg(t, pg)

	token, err := identity.GenerateGatewayToken()
	if err != nil {
		t.Fatalf("GenerateGatewayToken: %v", err)
	}
	gw, err := pg.RegisterGateway(ctx, store.RegisterGatewayInput{
		OrgID:            otherOrgID,
		Name:             "crossorg-gateway-" + identity.GatewayTokenDisplayPrefix(token),
		CredentialPrefix: identity.GatewayTokenDisplayPrefix(token),
		CredentialHash:   identity.HashToken(token),
	})
	if err != nil {
		t.Fatalf("RegisterGateway(other org): %v", err)
	}

	_, err = pg.GetGateway(ctx, seededOrgID, gw.ID)
	assertNotFound(t, err, "GetGateway across orgs")

	_, err = pg.UpdateGatewayHeartbeat(ctx, seededOrgID, gw.ID, store.GatewayHeartbeatInput{Version: "9.9.9"})
	assertNotFound(t, err, "UpdateGatewayHeartbeat across orgs")
}

// A policy snapshot must contain only the requested org's rules - this is what
// a distributed gateway enforces against, so a leak here would apply another
// tenant's policy to live traffic.
func TestPolicySnapshotIsOrgScoped(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()
	otherOrgID, _, _ := setupOtherOrg(t, pg)

	rules, err := pg.ListRulesForOrgSnapshot(ctx, otherOrgID)
	if err != nil {
		t.Fatalf("ListRulesForOrgSnapshot: %v", err)
	}
	for _, r := range rules {
		if r.OrgID != otherOrgID {
			t.Fatalf("snapshot for %q contained a rule from org %q", otherOrgID, r.OrgID)
		}
	}
}

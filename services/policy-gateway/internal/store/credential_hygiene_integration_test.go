//go:build integration

package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/identity"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
)

// Phase 5.11 acceptance: "no plaintext agent/gateway credentials in DB".
//
// Asserted against real Postgres rather than by reading the insert statements,
// because the property that matters is what actually landed on disk.

func TestAgentCredentialIsStoredOnlyAsHash(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()

	token, err := identity.GenerateAgentToken()
	if err != nil {
		t.Fatalf("GenerateAgentToken: %v", err)
	}

	agents, err := pg.ListAgents(ctx, store.ListAgentsInput{OrgID: seededOrgID, Limit: 1})
	if err != nil || len(agents) == 0 {
		t.Fatalf("need a seeded agent: %v", err)
	}

	cred, err := pg.CreateAgentCredential(ctx, store.CreateAgentCredentialInput{
		OrgID:       seededOrgID,
		AgentID:     agents[0].ID,
		TokenPrefix: identity.TokenDisplayPrefix(token),
		TokenHash:   identity.HashAgentToken(token),
		CreatedBy:   seededAdminID,
	}, store.AuditInput{OrgID: seededOrgID, EventType: "agent_credential_created", ActorID: seededAdminID})
	if err != nil {
		t.Fatalf("CreateAgentCredential: %v", err)
	}

	if cred.TokenHash != identity.HashAgentToken(token) {
		t.Fatal("stored hash does not match the token's hash")
	}
	if cred.TokenHash == token {
		t.Fatal("token_hash column holds the plaintext token")
	}
	if strings.Contains(cred.TokenHash, token) {
		t.Fatal("stored hash contains the plaintext token")
	}

	// The display prefix is a lookup aid shown in the console. It must be a
	// truncation only - never enough material to reconstruct the credential.
	if len(cred.TokenPrefix) >= len(token) {
		t.Fatalf("token_prefix (%d chars) is not a truncation of the token (%d chars)",
			len(cred.TokenPrefix), len(token))
	}

	// And the credential must be resolvable by hash, proving the hash is what
	// authentication actually matches on.
	found, err := pg.GetAgentCredentialByHash(ctx, identity.HashAgentToken(token))
	if err != nil {
		t.Fatalf("GetAgentCredentialByHash: %v", err)
	}
	if found.ID != cred.ID {
		t.Fatalf("hash lookup returned %q, want %q", found.ID, cred.ID)
	}

	// A near-miss hash must not resolve.
	if _, err := pg.GetAgentCredentialByHash(ctx, identity.HashAgentToken(token+"x")); err == nil {
		t.Fatal("a different token resolved to the same credential")
	}
}

func TestGatewayCredentialIsStoredOnlyAsHash(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()

	token, err := identity.GenerateGatewayToken()
	if err != nil {
		t.Fatalf("GenerateGatewayToken: %v", err)
	}

	gw, err := pg.RegisterGateway(ctx, store.RegisterGatewayInput{
		OrgID:            seededOrgID,
		Name:             "hygiene-test-" + identity.GatewayTokenDisplayPrefix(token),
		CredentialPrefix: identity.GatewayTokenDisplayPrefix(token),
		CredentialHash:   identity.HashToken(token),
	})
	if err != nil {
		t.Fatalf("RegisterGateway: %v", err)
	}

	if gw.CredentialHash == token {
		t.Fatal("credential_hash column holds the plaintext gateway token")
	}
	if gw.CredentialHash != identity.HashToken(token) {
		t.Fatal("stored gateway hash does not match the token's hash")
	}
	if len(gw.CredentialPrefix) >= len(token) {
		t.Fatal("credential_prefix is not a truncation of the token")
	}
}

// Agent and gateway credentials are separate trust domains: a gateway token
// must not authenticate as an agent, nor an agent token as a gateway, even
// though both are opaque bearer strings hashed the same way.
func TestCredentialTrustDomainsDoNotCross(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()

	gatewayToken, err := identity.GenerateGatewayToken()
	if err != nil {
		t.Fatalf("GenerateGatewayToken: %v", err)
	}
	if _, err := pg.RegisterGateway(ctx, store.RegisterGatewayInput{
		OrgID:            seededOrgID,
		Name:             "crossdomain-" + identity.GatewayTokenDisplayPrefix(gatewayToken),
		CredentialPrefix: identity.GatewayTokenDisplayPrefix(gatewayToken),
		CredentialHash:   identity.HashToken(gatewayToken),
	}); err != nil {
		t.Fatalf("RegisterGateway: %v", err)
	}

	// A valid gateway token must not resolve as an agent credential.
	if _, err := pg.GetAgentCredentialByHash(ctx, identity.HashToken(gatewayToken)); err == nil {
		t.Fatal("a gateway credential resolved as an agent credential")
	}

	// And an agent token must not resolve as a gateway.
	agentToken, err := identity.GenerateAgentToken()
	if err != nil {
		t.Fatalf("GenerateAgentToken: %v", err)
	}
	if _, err := pg.GetGatewayByCredentialHash(ctx, identity.HashAgentToken(agentToken)); err == nil {
		t.Fatal("an agent credential resolved as a gateway")
	}
}

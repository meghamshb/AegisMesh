package identity_test

import (
	"strings"
	"testing"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/identity"
)

func TestGenerateAgentTokenHasPrefix(t *testing.T) {
	token, err := identity.GenerateAgentToken()
	if err != nil {
		t.Fatalf("GenerateAgentToken() error = %v", err)
	}
	if !strings.HasPrefix(token, "clr_agent_") {
		t.Fatalf("token = %q, want clr_agent_ prefix", token)
	}
}

func TestGenerateAgentTokenIsUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		token, err := identity.GenerateAgentToken()
		if err != nil {
			t.Fatalf("GenerateAgentToken() error = %v", err)
		}
		if seen[token] {
			t.Fatalf("duplicate token generated: %q", token)
		}
		seen[token] = true
	}
}

func TestHashAgentTokenDeterministic(t *testing.T) {
	token := "clr_agent_fixed-value-for-test"
	if identity.HashAgentToken(token) != identity.HashAgentToken(token) {
		t.Fatal("HashAgentToken should be deterministic for the same input")
	}
}

func TestHashAgentTokenNotEqualPlaintext(t *testing.T) {
	token := "clr_agent_fixed-value-for-test"
	if identity.HashAgentToken(token) == token {
		t.Fatal("hash must not equal plaintext token")
	}
}

func TestHashAgentTokenDiffersForDifferentTokens(t *testing.T) {
	a, err := identity.GenerateAgentToken()
	if err != nil {
		t.Fatalf("GenerateAgentToken() error = %v", err)
	}
	b, err := identity.GenerateAgentToken()
	if err != nil {
		t.Fatalf("GenerateAgentToken() error = %v", err)
	}
	if identity.HashAgentToken(a) == identity.HashAgentToken(b) {
		t.Fatal("hashes of two distinct tokens should not collide")
	}
}

func TestTokenDisplayPrefix(t *testing.T) {
	token := "clr_agent_w8F1eQsSomeLongerRandomSuffix"
	prefix := identity.TokenDisplayPrefix(token)
	if !strings.HasPrefix(token, prefix) {
		t.Fatalf("display prefix %q is not a prefix of token", prefix)
	}
	if len(prefix) >= len(token) {
		t.Fatalf("display prefix should be shorter than the full token")
	}
}

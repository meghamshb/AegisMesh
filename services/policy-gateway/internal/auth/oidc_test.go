package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/auth"
)

// These tests mint real RSA-signed JWTs and verify them through the real
// go-oidc path against a locally served JWKS. Nothing is stubbed out at the
// crypto boundary, so signature, issuer, audience, and expiry checks are
// genuinely exercised - which is the only way to know the seam rejects what it
// should.

const (
	testIssuerPath = "/issuer"
	testAudience   = "clearance-console"
	testKeyID      = "test-key-1"
)

type idp struct {
	key    *rsa.PrivateKey
	server *httptest.Server
	issuer string
}

func newIDP(t *testing.T) *idp {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	p := &idp{key: key}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                p.issuer,
			"jwks_uri":                              p.server.URL + "/jwks",
			"authorization_endpoint":                p.server.URL + "/auth",
			"token_endpoint":                        p.server.URL + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		pub := key.Public().(*rsa.PublicKey)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": testKeyID,
				"alg": "RS256",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			}},
		})
	})

	p.server = httptest.NewServer(mux)
	p.issuer = p.server.URL
	t.Cleanup(p.server.Close)
	return p
}

func (p *idp) verifier(t *testing.T) *auth.OIDCVerifier {
	t.Helper()
	v, err := auth.NewOIDCVerifier(context.Background(), p.issuer, testAudience, "")
	if err != nil {
		t.Fatalf("NewOIDCVerifier: %v", err)
	}
	return v
}

type tokenOpts struct {
	subject       string
	audience      any
	issuer        string
	expiresAt     time.Time
	email         string
	emailVerified *bool
	signWith      *rsa.PrivateKey
	alg           string
}

func (p *idp) mint(t *testing.T, o tokenOpts) string {
	t.Helper()

	if o.issuer == "" {
		o.issuer = p.issuer
	}
	if o.audience == nil {
		o.audience = testAudience
	}
	if o.expiresAt.IsZero() {
		o.expiresAt = time.Now().Add(time.Hour)
	}
	if o.signWith == nil {
		o.signWith = p.key
	}
	if o.alg == "" {
		o.alg = "RS256"
	}

	claims := map[string]any{
		"iss": o.issuer,
		"sub": o.subject,
		"aud": o.audience,
		"exp": o.expiresAt.Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
	}
	if o.email != "" {
		claims["email"] = o.email
	}
	if o.emailVerified != nil {
		claims["email_verified"] = *o.emailVerified
	}

	return signJWT(t, o.alg, testKeyID, claims, o.signWith)
}

func TestVerifiesGenuineToken(t *testing.T) {
	p := newIDP(t)
	verified := true

	raw := p.mint(t, tokenOpts{
		subject:       "alice-subject",
		email:         "Alice@Example.com",
		emailVerified: &verified,
	})

	claims, err := p.verifier(t).Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "alice-subject" {
		t.Fatalf("subject = %q", claims.Subject)
	}
	if claims.Issuer != p.issuer {
		t.Fatalf("issuer = %q, want %q", claims.Issuer, p.issuer)
	}
	if claims.Email != "Alice@Example.com" || !claims.EmailVerified {
		t.Fatalf("email = %q verified = %v", claims.Email, claims.EmailVerified)
	}
}

// The external subject must be namespaced by issuer. Without this, a second
// (attacker-controlled) issuer could mint a token with the same subject value
// and take over an existing account.
func TestExternalSubjectIsNamespacedByIssuer(t *testing.T) {
	a := auth.Claims{Issuer: "https://idp-a.example", Subject: "shared-id"}
	b := auth.Claims{Issuer: "https://idp-b.example", Subject: "shared-id"}

	if a.ExternalSubject() == b.ExternalSubject() {
		t.Fatal("identical subjects from different issuers produced the same key; " +
			"a rogue issuer could impersonate an existing account")
	}
	if !strings.Contains(a.ExternalSubject(), "idp-a.example") {
		t.Fatalf("external subject %q does not carry the issuer", a.ExternalSubject())
	}
}

func TestRejectsTokenSignedByAnotherKey(t *testing.T) {
	p := newIDP(t)
	attacker, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate attacker key: %v", err)
	}

	raw := p.mint(t, tokenOpts{subject: "alice-subject", signWith: attacker})

	if _, err := p.verifier(t).Verify(context.Background(), raw); err == nil {
		t.Fatal("a token signed by an unknown key was accepted")
	}
}

// Algorithm confusion: an unsigned token must never be accepted, no matter how
// well-formed its claims are.
func TestRejectsUnsignedToken(t *testing.T) {
	p := newIDP(t)

	claims := map[string]any{
		"iss": p.issuer,
		"sub": "alice-subject",
		"aud": testAudience,
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	body, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(body)
	raw := header + "." + payload + "."

	if _, err := p.verifier(t).Verify(context.Background(), raw); err == nil {
		t.Fatal("an alg=none token was accepted")
	}
}

func TestRejectsExpiredToken(t *testing.T) {
	p := newIDP(t)
	raw := p.mint(t, tokenOpts{
		subject:   "alice-subject",
		expiresAt: time.Now().Add(-time.Minute),
	})

	if _, err := p.verifier(t).Verify(context.Background(), raw); err == nil {
		t.Fatal("an expired token was accepted")
	}
}

func TestRejectsWrongAudience(t *testing.T) {
	p := newIDP(t)
	raw := p.mint(t, tokenOpts{subject: "alice-subject", audience: "some-other-app"})

	if _, err := p.verifier(t).Verify(context.Background(), raw); err == nil {
		t.Fatal("a token minted for a different audience was accepted")
	}
}

func TestRejectsWrongIssuer(t *testing.T) {
	p := newIDP(t)
	// Signed with the right key, but claiming a different issuer.
	raw := p.mint(t, tokenOpts{subject: "alice-subject", issuer: "https://evil.example"})

	if _, err := p.verifier(t).Verify(context.Background(), raw); err == nil {
		t.Fatal("a token claiming a different issuer was accepted")
	}
}

func TestRejectsGarbage(t *testing.T) {
	p := newIDP(t)
	v := p.verifier(t)

	for _, raw := range []string{"", "not-a-jwt", "a.b.c", "Bearer something"} {
		if _, err := v.Verify(context.Background(), raw); err == nil {
			t.Fatalf("malformed token %q was accepted", raw)
		}
	}
}

// A token may legitimately omit email - it is not a required OIDC claim - and
// that must not fail verification, only leave the email empty.
func TestTokenWithoutEmailStillVerifies(t *testing.T) {
	p := newIDP(t)
	raw := p.mint(t, tokenOpts{subject: "alice-subject"})

	claims, err := p.verifier(t).Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Email != "" || claims.EmailVerified {
		t.Fatalf("expected no email, got %q verified=%v", claims.Email, claims.EmailVerified)
	}
}

// Ensures the verifier really is provider-neutral: pointing it at a different
// issuer URL works with no code change.
func TestWorksAgainstADifferentProvider(t *testing.T) {
	other := newIDP(t)
	raw := other.mint(t, tokenOpts{subject: "bob-subject"})

	claims, err := other.verifier(t).Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("Verify against second provider: %v", err)
	}
	if claims.Subject != "bob-subject" {
		t.Fatalf("subject = %q", claims.Subject)
	}
}

var _ = oidc.KeySet(nil)

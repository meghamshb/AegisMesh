package auth

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

// OIDCVerifier validates tokens against an OpenID Connect provider.
//
// Verification is delegated to github.com/coreos/go-oidc rather than
// hand-rolled. JWT verification looks simple and is not: the classic failures
// are algorithm confusion (accepting `alg: none`, or an HMAC token verified
// with a public key as the secret), skipping audience checks, and mishandling
// JWKS key rotation. go-oidc handles all three, and gets security review this
// codebase cannot give a bespoke implementation.
//
// Nothing here is provider-specific (§5.13.3). Discovery, key fetching, and
// claim names are all standard OIDC, so Entra ID, Google, Auth0, Keycloak, and
// Okta work through the same path with different configuration.
type OIDCVerifier struct {
	verifier *oidc.IDTokenVerifier
	issuer   string
}

// NewOIDCVerifier performs OIDC discovery against issuerURL and returns a
// verifier bound to the expected audience.
//
// Discovery happens once, at startup, and a failure is fatal to the caller by
// design: a control plane that cannot reach its identity provider must not
// start up and quietly accept nothing (or worse, fall back to a weaker mode).
// That matches the fail-closed posture the data plane already takes with its
// policy snapshot.
func NewOIDCVerifier(ctx context.Context, issuerURL, clientID, audience string) (*OIDCVerifier, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery against %q: %w", issuerURL, err)
	}

	// OIDC_AUDIENCE wins when set, because access tokens are often issued to
	// an API audience distinct from the UI's client id. Falling back to the
	// client id covers the common case where they are the same.
	expected := audience
	if expected == "" {
		expected = clientID
	}

	return &OIDCVerifier{
		verifier: provider.Verifier(&oidc.Config{ClientID: expected}),
		issuer:   issuerURL,
	}, nil
}

// NewOIDCVerifierFromKeySet builds a verifier around an explicit key set,
// skipping discovery. Used by tests, which serve their own JWKS.
func NewOIDCVerifierFromKeySet(keySet oidc.KeySet, issuerURL, audience string) *OIDCVerifier {
	return &OIDCVerifier{
		verifier: oidc.NewVerifier(issuerURL, keySet, &oidc.Config{ClientID: audience}),
		issuer:   issuerURL,
	}
}

// Verify checks signature, issuer, audience, and expiry, then extracts the
// identity claims. go-oidc performs the first four; anything it rejects never
// reaches the claim extraction below.
func (v *OIDCVerifier) Verify(ctx context.Context, rawToken string) (Claims, error) {
	idToken, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		return Claims{}, err
	}

	var extra struct {
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
	}
	if err := idToken.Claims(&extra); err != nil {
		// A token can legitimately omit email (it is not a required OIDC
		// claim), so failing to decode optional claims must not fail the
		// whole verification - the signature and standard claims already
		// passed.
		extra.Email = ""
	}

	verified := false
	if extra.EmailVerified != nil {
		verified = *extra.EmailVerified
	}

	return Claims{
		Issuer:        idToken.Issuer,
		Subject:       idToken.Subject,
		Email:         extra.Email,
		EmailVerified: verified,
	}, nil
}

// Issuer reports the configured issuer, for surfacing in /api/v1/auth/config.
func (v *OIDCVerifier) Issuer() string { return v.issuer }

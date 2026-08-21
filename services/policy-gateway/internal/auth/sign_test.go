package auth_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// signJWT produces a real RS256-signed compact JWT.
//
// This is test-only signing, and only ever used to *produce* input for the
// verifier under test - the production path never signs anything. Minting real
// tokens rather than stubbing the verifier is what makes the rejection tests
// meaningful: a stub would happily "reject" whatever we told it to.
func signJWT(t *testing.T, alg, kid string, claims map[string]any, key *rsa.PrivateKey) string {
	t.Helper()

	header := map[string]any{"alg": alg, "typ": "JWT", "kid": kid}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)

	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

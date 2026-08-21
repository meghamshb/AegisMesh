package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const (
	tokenPrefix      = "clr_agent_"
	tokenRandBytes   = 32
	displayPrefixLen = len(tokenPrefix) + 4
)

// GenerateAgentToken returns a new opaque agent credential of the form
// "clr_agent_<random>", using crypto/rand for the random component.
func GenerateAgentToken() (string, error) {
	buf := make([]byte, tokenRandBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate agent token: %w", err)
	}
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

// HashAgentToken returns the SHA-256 hex digest of a token. Only this hash
// is ever persisted; the plaintext token is never stored.
func HashAgentToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// TokenDisplayPrefix returns a short, non-secret prefix of the token
// (e.g. "clr_agent_w8F1") suitable for display and audit metadata.
func TokenDisplayPrefix(token string) string {
	if len(token) <= displayPrefixLen {
		return token
	}
	return token[:displayPrefixLen]
}

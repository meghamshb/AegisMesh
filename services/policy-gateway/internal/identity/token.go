package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const (
	tokenPrefix        = "clr_agent_"
	gatewayTokenPrefix = "clr_gateway_"
	tokenRandBytes     = 32
	displayPrefixLen   = len(tokenPrefix) + 4
	gatewayDisplayLen  = len(gatewayTokenPrefix) + 4
)

// GenerateAgentToken returns a new opaque agent credential of the form
// "clr_agent_<random>", using crypto/rand for the random component.
func GenerateAgentToken() (string, error) {
	return generateToken(tokenPrefix)
}

// GenerateGatewayToken returns a new opaque gateway credential of the form
// "clr_gateway_<random>". Gateway credentials are a separate trust domain
// from agent credentials: they authenticate a gateway process to the
// control plane, never an individual agent.
func GenerateGatewayToken() (string, error) {
	return generateToken(gatewayTokenPrefix)
}

func generateToken(prefix string) (string, error) {
	buf := make([]byte, tokenRandBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

// HashAgentToken returns the SHA-256 hex digest of a token. Only this hash
// is ever persisted; the plaintext token is never stored. Despite the name,
// this hash is not agent-specific - it is also used for gateway credentials
// (aliased below as HashToken for clarity at those call sites).
func HashAgentToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// HashToken is an alias for HashAgentToken, used at gateway-credential call
// sites where naming it "agent" would be misleading.
func HashToken(token string) string {
	return HashAgentToken(token)
}

// TokenDisplayPrefix returns a short, non-secret prefix of the token
// (e.g. "clr_agent_w8F1") suitable for display and audit metadata.
func TokenDisplayPrefix(token string) string {
	if len(token) <= displayPrefixLen {
		return token
	}
	return token[:displayPrefixLen]
}

// GatewayTokenDisplayPrefix is TokenDisplayPrefix's counterpart for the
// longer "clr_gateway_" prefix.
func GatewayTokenDisplayPrefix(token string) string {
	if len(token) <= gatewayDisplayLen {
		return token
	}
	return token[:gatewayDisplayLen]
}

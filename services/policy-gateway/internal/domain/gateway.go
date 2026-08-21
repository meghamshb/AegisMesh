package domain

import "time"

// Gateway is a registered data-plane enforcement point. Its credential is a
// separate trust domain from agent credentials: a gateway credential
// authenticates the gateway process itself to the control plane, never an
// individual Hermes agent.
type Gateway struct {
	ID               string         `json:"id"`
	OrgID            string         `json:"org_id"`
	Name             string         `json:"name"`
	Status           string         `json:"status"`
	CredentialPrefix string         `json:"credential_prefix"`
	CredentialHash   string         `json:"-"`
	Version          string         `json:"version,omitempty"`
	MetadataJSON     []byte         `json:"-"`
	Metadata         map[string]any `json:"metadata"`
	LastSeenAt       *time.Time     `json:"last_seen_at,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
	RevokedAt        *time.Time     `json:"revoked_at,omitempty"`
}

type RegisterGatewayBody struct {
	Name     string         `json:"name"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type GatewayHeartbeatBody struct {
	Version       string `json:"version,omitempty"`
	ActiveAgents  int    `json:"active_agents,omitempty"`
	PolicyVersion int64  `json:"policy_version,omitempty"`
}

// PolicySnapshot is the org-scoped, versioned view of policy_rules a gateway
// fetches and caches locally (Phase 5.9). It intentionally excludes
// request-history state (standing denies, approve-once grants) - those stay
// server-side; the snapshot is only the persistent allow/deny rule set.
type PolicySnapshot struct {
	OrgID       string       `json:"org_id"`
	Version     int64        `json:"version"`
	GeneratedAt time.Time    `json:"generated_at"`
	Rules       []PolicyRule `json:"rules"`
}

// AuthenticatedGateway is the trusted identity resolved from a valid gateway
// credential - the data-plane analogue of AuthenticatedAgent in the identity
// package, kept in domain since both control- and data-plane code use it.
type AuthenticatedGateway struct {
	GatewayID string
	OrgID     string
}

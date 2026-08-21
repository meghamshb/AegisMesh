// Package remoteidentity is the data-plane client half of Phase 5.9.10: a
// distributed gateway hashes an agent token locally and asks the control
// plane's internal API to resolve it, instead of querying Postgres
// directly. The plaintext token itself never crosses the network - only its
// SHA-256 hash does.
package remoteidentity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/config"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/identity"
)

// Client calls POST /api/internal/v1/agents/authenticate.
type Client struct {
	BaseURL      string
	GatewayToken string
	HTTPClient   *http.Client
}

func NewClient(baseURL, gatewayToken string) *Client {
	return &Client{
		BaseURL:      strings.TrimRight(baseURL, "/"),
		GatewayToken: gatewayToken,
		HTTPClient:   &http.Client{Timeout: 10 * time.Second},
	}
}

type authenticateResponse struct {
	AgentID     string `json:"agent_id"`
	UserID      string `json:"user_id"`
	OrgID       string `json:"org_id"`
	AgentStatus string `json:"agent_status"`
	UserStatus  string `json:"user_status"`
	OrgStatus   string `json:"org_status"`
}

// Authenticate resolves an agent token's SHA-256 hash to its identity via
// the control plane. Errors are the same identity.Err* sentinels the
// direct-DB path returns, so callers don't need to branch on which path
// resolved the request.
func (c *Client) Authenticate(ctx context.Context, tokenHash string) (config.AgentIdentity, error) {
	body, err := json.Marshal(map[string]string{"token_hash": tokenHash})
	if err != nil {
		return config.AgentIdentity{}, fmt.Errorf("marshal authenticate request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/internal/v1/agents/authenticate", bytes.NewReader(body))
	if err != nil {
		return config.AgentIdentity{}, fmt.Errorf("build authenticate request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.GatewayToken)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return config.AgentIdentity{}, fmt.Errorf("call authenticate: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return config.AgentIdentity{}, identity.ErrInvalidToken
	case http.StatusForbidden:
		return config.AgentIdentity{}, identity.ErrAgentRevoked
	default:
		return config.AgentIdentity{}, fmt.Errorf("authenticate: unexpected status %d", resp.StatusCode)
	}

	var parsed authenticateResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return config.AgentIdentity{}, fmt.Errorf("decode authenticate response: %w", err)
	}

	return config.AgentIdentity{
		OrgID:   parsed.OrgID,
		UserID:  parsed.UserID,
		AgentID: parsed.AgentID,
	}, nil
}

type cacheEntry struct {
	identity  config.AgentIdentity
	expiresAt time.Time
}

// CachedClient wraps Client with a short-TTL, per-token-hash cache (Phase
// 5.9.11), so a busy agent doesn't cause a control-plane round trip on
// every single proxied request.
type CachedClient struct {
	client *Client
	ttl    time.Duration

	mu    sync.Mutex
	cache map[string]cacheEntry
}

func NewCachedClient(client *Client, ttl time.Duration) *CachedClient {
	return &CachedClient{client: client, ttl: ttl, cache: make(map[string]cacheEntry)}
}

func (c *CachedClient) Authenticate(ctx context.Context, tokenHash string) (config.AgentIdentity, error) {
	c.mu.Lock()
	if entry, ok := c.cache[tokenHash]; ok && time.Now().Before(entry.expiresAt) {
		c.mu.Unlock()
		return entry.identity, nil
	}
	c.mu.Unlock()

	id, err := c.client.Authenticate(ctx, tokenHash)
	if err != nil {
		// Never cache negative results: a just-revoked credential must stop
		// working immediately, not linger as a cached success from before
		// revocation, and a transient network error shouldn't get "stuck".
		return config.AgentIdentity{}, err
	}

	c.mu.Lock()
	c.cache[tokenHash] = cacheEntry{identity: id, expiresAt: time.Now().Add(c.ttl)}
	c.mu.Unlock()
	return id, nil
}

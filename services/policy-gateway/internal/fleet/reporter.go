// Package fleet is the gateway-side half of Phase 5.10 fleet visibility: it
// tells the control plane that this gateway is alive, which build it is
// running, which policy version it is actually enforcing, and how many agents
// it has served recently.
//
// This is reporting, not enforcement. A gateway that cannot reach the control
// plane keeps proxying against its last-known-good snapshot (Phase 5.9); it
// simply stops appearing fresh in the Gateways tab. Heartbeat failures are
// therefore logged, never fatal.
package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// PolicyVersionSource reports the policy version currently in force. Satisfied
// by policycache.Cache.
type PolicyVersionSource interface {
	Health() map[string]any
}

// AgentCounter reports how many distinct agents have been served since the
// last call, and resets the window. Satisfied by proxy.Handler.
type AgentCounter interface {
	DrainRecentAgentCount() int
}

type Reporter struct {
	baseURL      string
	token        string
	buildVersion string
	client       *http.Client
	policy       PolicyVersionSource
	agents       AgentCounter
	logger       *slog.Logger

	mu        sync.RWMutex
	gatewayID string
	name      string
}

func NewReporter(baseURL, token, buildVersion string, policy PolicyVersionSource, agents AgentCounter, logger *slog.Logger) *Reporter {
	if logger == nil {
		logger = slog.Default()
	}
	return &Reporter{
		baseURL:      strings.TrimRight(baseURL, "/"),
		token:        token,
		buildVersion: buildVersion,
		client:       &http.Client{Timeout: 5 * time.Second},
		policy:       policy,
		agents:       agents,
		logger:       logger,
	}
}

// Identify resolves this gateway's own id from its credential. It is separate
// from Start so callers can surface a misconfigured credential at boot rather
// than only in a background log line.
func (r *Reporter) Identify(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.baseURL+"/api/internal/v1/gateways/self", nil)
	if err != nil {
		return fmt.Errorf("build gateway self request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+r.token)

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("resolve gateway identity: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("resolve gateway identity: control plane returned %s", resp.Status)
	}

	var body struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("decode gateway identity: %w", err)
	}
	if body.ID == "" {
		return fmt.Errorf("control plane returned an empty gateway id")
	}

	r.mu.Lock()
	r.gatewayID = body.ID
	r.name = body.Name
	r.mu.Unlock()
	return nil
}

// GatewayID returns the resolved id, empty until Identify succeeds.
func (r *Reporter) GatewayID() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.gatewayID
}

// Name returns the resolved gateway name, empty until Identify succeeds.
func (r *Reporter) Name() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.name
}

// Start sends a heartbeat immediately and then on every tick until ctx ends.
func (r *Reporter) Start(ctx context.Context, interval time.Duration) {
	go func() {
		if err := r.beat(ctx); err != nil {
			r.logger.Warn("initial gateway heartbeat failed", "error", err)
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := r.beat(ctx); err != nil {
					r.logger.Warn("gateway heartbeat failed", "error", err)
				}
			}
		}
	}()
}

func (r *Reporter) beat(ctx context.Context) error {
	id := r.GatewayID()
	if id == "" {
		// Identity was not resolved at boot (control plane was down). Retry it
		// here so the gateway rejoins the fleet view without a restart.
		if err := r.Identify(ctx); err != nil {
			return err
		}
		id = r.GatewayID()
	}

	payload := map[string]any{
		"version":        r.buildVersion,
		"policy_version": r.currentPolicyVersion(),
		"active_agents":  r.agents.DrainRecentAgentCount(),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode heartbeat: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		r.baseURL+"/api/internal/v1/gateways/"+id+"/heartbeat", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build heartbeat request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("send heartbeat: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat rejected: control plane returned %s", resp.Status)
	}
	return nil
}

func (r *Reporter) currentPolicyVersion() int64 {
	if r.policy == nil {
		return 0
	}
	health := r.policy.Health()
	if v, ok := health["version"].(int64); ok {
		return v
	}
	return 0
}

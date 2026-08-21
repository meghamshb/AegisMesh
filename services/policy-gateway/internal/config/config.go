package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultListenAddr        = ":8080"
	defaultGatewayListenAddr = ":8081"
	defaultServiceName       = "policy-gateway"
	defaultServiceVer        = "0.6.1-phase4"
	defaultPostgresDSN       = "postgres://hermes:hermes@postgres:5432/hermes_policy?sslmode=disable"
	defaultReadTimeout       = 15 * time.Second
	defaultWriteTimeout      = 15 * time.Second
	defaultIdleTimeout       = 60 * time.Second
	defaultShutdownGrace     = 10 * time.Second

	defaultOrgID   = "11111111-1111-1111-1111-111111111010"
	defaultUserID  = "11111111-1111-1111-1111-111111111001"
	defaultAgentID = "11111111-1111-1111-1111-111111111020"
	defaultAdminID = "11111111-1111-1111-1111-111111111002"

	defaultPolicyRefreshInterval = 5 * time.Second
	defaultPolicyMaxStale        = 15 * time.Minute
	defaultAgentIdentityCacheTTL = 10 * time.Second
	defaultHeartbeatInterval     = 10 * time.Second

	// Control-plane authentication modes (Phase 5.13). dev-token keeps the
	// shared static token for local work; oidc requires a verified JWT from a
	// real identity provider. There is deliberately no "off".
	AuthModeDevToken = "dev-token"
	AuthModeOIDC     = "oidc"

	// Rate limits (Phase 5.11.2). Generous enough that an operator clicking
	// through the console never notices, tight enough that credential
	// guessing and bulk credential minting are not free.
	defaultAuthFailureLimit = 10
	defaultMutationLimit    = 60
	defaultRateLimitWindow  = time.Minute
)

type AgentIdentity struct {
	OrgID   string
	UserID  string
	AgentID string
}

type Config struct {
	Mode                  string
	ListenAddr            string
	GatewayListenAddr     string
	ServiceName           string
	ServiceVersion        string
	PostgresDSN           string
	ReadTimeout           time.Duration
	WriteTimeout          time.Duration
	IdleTimeout           time.Duration
	ShutdownGrace         time.Duration
	ProxyEnabled          bool
	Identity              AgentIdentity
	AdminID               string
	AdminToken            string
	ApproverHeader        string
	AllowIdentityOverride bool
	AgentIDHeader         string
	UserIDHeader          string
	AgentAuthMode         string

	// Fleet mode (Phase 5.9): when ControlPlaneURL is set and Mode is
	// "gateway", the proxy resolves agent identity via the control plane's
	// internal API instead of a direct DB lookup. GatewayToken authenticates
	// this process to that API. Policy *rule evaluation* still reads
	// directly from Postgres in this phase (see internal/policycache for the
	// snapshot cache itself, wired in starting Phase 5.10's fleet demo).
	ControlPlaneURL       string
	GatewayToken          string
	PolicyRefreshInterval time.Duration
	PolicyMaxStale        time.Duration
	AgentIdentityCacheTTL time.Duration
	HeartbeatInterval     time.Duration
	AuthMode              string
	OIDCIssuerURL         string
	OIDCClientID          string
	OIDCAudience          string
	AuthFailureLimit      int
	MutationLimit         int
	RateLimitWindow       time.Duration
}

const (
	AgentAuthModeStatic = "static"
	AgentAuthModeToken  = "token"
)

// CLEARANCE_MODE decides which HTTP surfaces this process binds (Phase 5.8):
//   - all: both the control-plane API and the data-plane proxy on ListenAddr
//     (the existing single-process monolith behavior, unchanged default).
//   - control: only the control-plane API (users/agents/rules/requests/audit,
//     plus the embedded UI) on ListenAddr. No proxy forwarding.
//   - gateway: only the data-plane proxy listener on GatewayListenAddr. No
//     admin API is exposed on this listener at all.
const (
	ModeAll     = "all"
	ModeControl = "control"
	ModeGateway = "gateway"
)

func Load() (Config, error) {
	readTimeout, err := durationEnv("GATEWAY_READ_TIMEOUT", defaultReadTimeout)
	if err != nil {
		return Config{}, err
	}
	writeTimeout, err := durationEnv("GATEWAY_WRITE_TIMEOUT", defaultWriteTimeout)
	if err != nil {
		return Config{}, err
	}
	idleTimeout, err := durationEnv("GATEWAY_IDLE_TIMEOUT", defaultIdleTimeout)
	if err != nil {
		return Config{}, err
	}
	shutdownGrace, err := durationEnv("GATEWAY_SHUTDOWN_GRACE", defaultShutdownGrace)
	if err != nil {
		return Config{}, err
	}
	proxyEnabled, err := boolEnv("GATEWAY_PROXY_ENABLED", true)
	if err != nil {
		return Config{}, err
	}
	policyRefreshInterval, err := durationEnv("CLEARANCE_POLICY_REFRESH_INTERVAL", defaultPolicyRefreshInterval)
	if err != nil {
		return Config{}, err
	}
	policyMaxStale, err := durationEnv("CLEARANCE_POLICY_MAX_STALE", defaultPolicyMaxStale)
	if err != nil {
		return Config{}, err
	}
	agentIdentityCacheTTL, err := durationEnv("CLEARANCE_AGENT_IDENTITY_CACHE_TTL", defaultAgentIdentityCacheTTL)
	if err != nil {
		return Config{}, err
	}
	heartbeatInterval, err := durationEnv("CLEARANCE_HEARTBEAT_INTERVAL", defaultHeartbeatInterval)
	if err != nil {
		return Config{}, err
	}
	rateLimitWindow, err := durationEnv("CLEARANCE_RATE_LIMIT_WINDOW", defaultRateLimitWindow)
	if err != nil {
		return Config{}, err
	}
	authFailureLimit, err := intEnv("CLEARANCE_AUTH_FAILURE_LIMIT", defaultAuthFailureLimit)
	if err != nil {
		return Config{}, err
	}
	mutationLimit, err := intEnv("CLEARANCE_MUTATION_LIMIT", defaultMutationLimit)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		Mode:              envOrDefault("CLEARANCE_MODE", ModeAll),
		ListenAddr:        envOrDefault("GATEWAY_LISTEN_ADDR", defaultListenAddr),
		GatewayListenAddr: envOrDefault("GATEWAY_PROXY_LISTEN_ADDR", defaultGatewayListenAddr),
		ServiceName:       envOrDefault("GATEWAY_SERVICE_NAME", defaultServiceName),
		ServiceVersion:    envOrDefault("GATEWAY_SERVICE_VERSION", defaultServiceVer),
		PostgresDSN:       envOrDefault("POSTGRES_DSN", defaultPostgresDSN),
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		ShutdownGrace:     shutdownGrace,
		ProxyEnabled:      proxyEnabled,
		Identity: AgentIdentity{
			OrgID:   envOrDefault("GATEWAY_ORG_ID", defaultOrgID),
			UserID:  envOrDefault("GATEWAY_USER_ID", defaultUserID),
			AgentID: envOrDefault("GATEWAY_AGENT_ID", defaultAgentID),
		},
		AdminID:               envOrDefault("GATEWAY_ADMIN_ID", defaultAdminID),
		AdminToken:            strings.TrimSpace(os.Getenv("GATEWAY_ADMIN_TOKEN")),
		ApproverHeader:        envOrDefault("GATEWAY_APPROVER_HEADER", "X-Gateway-Approver"),
		AllowIdentityOverride: boolEnvDefault("GATEWAY_ALLOW_IDENTITY_OVERRIDE", false),
		AgentIDHeader:         envOrDefault("GATEWAY_AGENT_ID_HEADER", "X-Gateway-Agent-Id"),
		UserIDHeader:          envOrDefault("GATEWAY_USER_ID_HEADER", "X-Gateway-User-Id"),
		AgentAuthMode:         envOrDefault("GATEWAY_AGENT_AUTH_MODE", AgentAuthModeStatic),
		ControlPlaneURL:       strings.TrimSpace(os.Getenv("CLEARANCE_CONTROL_URL")),
		GatewayToken:          strings.TrimSpace(os.Getenv("CLEARANCE_GATEWAY_TOKEN")),
		PolicyRefreshInterval: policyRefreshInterval,
		PolicyMaxStale:        policyMaxStale,
		AgentIdentityCacheTTL: agentIdentityCacheTTL,
		HeartbeatInterval:     heartbeatInterval,
		AuthMode:              envOrDefault("CLEARANCE_AUTH_MODE", AuthModeDevToken),
		OIDCIssuerURL:         strings.TrimSpace(os.Getenv("OIDC_ISSUER_URL")),
		OIDCClientID:          strings.TrimSpace(os.Getenv("OIDC_CLIENT_ID")),
		OIDCAudience:          strings.TrimSpace(os.Getenv("OIDC_AUDIENCE")),
		AuthFailureLimit:      authFailureLimit,
		MutationLimit:         mutationLimit,
		RateLimitWindow:       rateLimitWindow,
	}

	if cfg.PostgresDSN == "" {
		return Config{}, fmt.Errorf("POSTGRES_DSN must not be empty")
	}
	switch cfg.AuthMode {
	case AuthModeDevToken:
		// Nothing further required; the dev token may still be empty, which
		// leaves the control plane open. main.go warns loudly about both.
	case AuthModeOIDC:
		if cfg.OIDCIssuerURL == "" {
			return Config{}, fmt.Errorf("OIDC_ISSUER_URL is required when CLEARANCE_AUTH_MODE=%s", AuthModeOIDC)
		}
		if cfg.OIDCClientID == "" && cfg.OIDCAudience == "" {
			return Config{}, fmt.Errorf("OIDC_CLIENT_ID or OIDC_AUDIENCE is required when CLEARANCE_AUTH_MODE=%s", AuthModeOIDC)
		}
	default:
		return Config{}, fmt.Errorf("CLEARANCE_AUTH_MODE must be %q or %q, got %q",
			AuthModeDevToken, AuthModeOIDC, cfg.AuthMode)
	}
	if cfg.Identity.OrgID == "" || cfg.Identity.UserID == "" || cfg.Identity.AgentID == "" {
		return Config{}, fmt.Errorf("GATEWAY_ORG_ID, GATEWAY_USER_ID, and GATEWAY_AGENT_ID must not be empty")
	}
	if cfg.AgentAuthMode != AgentAuthModeStatic && cfg.AgentAuthMode != AgentAuthModeToken {
		return Config{}, fmt.Errorf("GATEWAY_AGENT_AUTH_MODE must be %q or %q", AgentAuthModeStatic, AgentAuthModeToken)
	}
	if cfg.Mode != ModeAll && cfg.Mode != ModeControl && cfg.Mode != ModeGateway {
		return Config{}, fmt.Errorf("CLEARANCE_MODE must be %q, %q, or %q", ModeAll, ModeControl, ModeGateway)
	}

	return cfg, nil
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func durationEnv(key string, fallback time.Duration) (time.Duration, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid duration: %w", key, err)
	}
	return parsed, nil
}

func boolEnv(key string, fallback bool) (bool, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false: %w", key, err)
	}
	return parsed, nil
}

func boolEnvDefault(key string, fallback bool) bool {
	parsed, err := boolEnv(key, fallback)
	if err != nil {
		return fallback
	}
	return parsed
}

// intEnv reads a non-negative integer environment variable. Zero disables the
// feature it governs (see ratelimit.New), so it is a valid value.
func intEnv(name string, fallback int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer, got %q", name, raw)
	}
	return parsed, nil
}

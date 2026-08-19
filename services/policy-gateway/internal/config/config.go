package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultListenAddr    = ":8080"
	defaultServiceName   = "policy-gateway"
	defaultServiceVer    = "0.6.1-phase4"
	defaultPostgresDSN   = "postgres://hermes:hermes@postgres:5432/hermes_policy?sslmode=disable"
	defaultReadTimeout   = 15 * time.Second
	defaultWriteTimeout  = 15 * time.Second
	defaultIdleTimeout   = 60 * time.Second
	defaultShutdownGrace = 10 * time.Second

	defaultOrgID   = "11111111-1111-1111-1111-111111111010"
	defaultUserID  = "11111111-1111-1111-1111-111111111001"
	defaultAgentID = "11111111-1111-1111-1111-111111111020"
	defaultAdminID = "11111111-1111-1111-1111-111111111002"
)

type AgentIdentity struct {
	OrgID   string
	UserID  string
	AgentID string
}

type Config struct {
	ListenAddr     string
	ServiceName    string
	ServiceVersion string
	PostgresDSN    string
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
	ShutdownGrace  time.Duration
	ProxyEnabled   bool
	Identity       AgentIdentity
	AdminID                string
	AdminToken             string
	ApproverHeader         string
	AllowIdentityOverride  bool
	AgentIDHeader          string
	UserIDHeader           string
}

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

	cfg := Config{
		ListenAddr:     envOrDefault("GATEWAY_LISTEN_ADDR", defaultListenAddr),
		ServiceName:    envOrDefault("GATEWAY_SERVICE_NAME", defaultServiceName),
		ServiceVersion: envOrDefault("GATEWAY_SERVICE_VERSION", defaultServiceVer),
		PostgresDSN:    envOrDefault("POSTGRES_DSN", defaultPostgresDSN),
		ReadTimeout:    readTimeout,
		WriteTimeout:   writeTimeout,
		IdleTimeout:    idleTimeout,
		ShutdownGrace:  shutdownGrace,
		ProxyEnabled:   proxyEnabled,
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
	}

	if cfg.PostgresDSN == "" {
		return Config{}, fmt.Errorf("POSTGRES_DSN must not be empty")
	}
	if cfg.Identity.OrgID == "" || cfg.Identity.UserID == "" || cfg.Identity.AgentID == "" {
		return Config{}, fmt.Errorf("GATEWAY_ORG_ID, GATEWAY_USER_ID, and GATEWAY_AGENT_ID must not be empty")
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

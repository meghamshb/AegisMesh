package config_test

import (
	"os"
	"testing"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/config"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("POSTGRES_DSN", "postgres://example")
	t.Setenv("GATEWAY_LISTEN_ADDR", "")
	t.Setenv("GATEWAY_PROXY_ENABLED", "")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.ListenAddr != ":8080" {
		t.Fatalf("ListenAddr = %q, want :8080", cfg.ListenAddr)
	}
	if cfg.Mode != config.ModeAll {
		t.Fatalf("Mode = %q, want %q (preserves pre-5.8 single-process behavior)", cfg.Mode, config.ModeAll)
	}
	if cfg.GatewayListenAddr != ":8081" {
		t.Fatalf("GatewayListenAddr = %q, want :8081", cfg.GatewayListenAddr)
	}
	if cfg.PostgresDSN != "postgres://example" {
		t.Fatalf("PostgresDSN = %q", cfg.PostgresDSN)
	}
	if cfg.ProxyEnabled != true {
		t.Fatalf("ProxyEnabled = %v, want true by default in phase 1", cfg.ProxyEnabled)
	}
	if cfg.ReadTimeout != 15*time.Second {
		t.Fatalf("ReadTimeout = %v", cfg.ReadTimeout)
	}
	if cfg.AgentAuthMode != config.AgentAuthModeStatic {
		t.Fatalf("AgentAuthMode = %q, want %q (static by default preserves pre-5.4 behavior)", cfg.AgentAuthMode, config.AgentAuthModeStatic)
	}
}

func TestLoadAgentAuthModeToken(t *testing.T) {
	t.Setenv("POSTGRES_DSN", "postgres://example")
	t.Setenv("GATEWAY_AGENT_AUTH_MODE", "token")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.AgentAuthMode != config.AgentAuthModeToken {
		t.Fatalf("AgentAuthMode = %q, want %q", cfg.AgentAuthMode, config.AgentAuthModeToken)
	}
}

func TestLoadRejectsInvalidAgentAuthMode(t *testing.T) {
	t.Setenv("POSTGRES_DSN", "postgres://example")
	t.Setenv("GATEWAY_AGENT_AUTH_MODE", "bogus")

	if _, err := config.Load(); err == nil {
		t.Fatal("expected invalid agent auth mode error")
	}
}

func TestLoadCustomProxyFlag(t *testing.T) {
	t.Setenv("POSTGRES_DSN", "postgres://example")
	t.Setenv("GATEWAY_PROXY_ENABLED", "true")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.ProxyEnabled {
		t.Fatal("expected proxy enabled")
	}

	_ = os.Unsetenv("GATEWAY_PROXY_ENABLED")
}

func TestLoadRejectsInvalidDuration(t *testing.T) {
	t.Setenv("POSTGRES_DSN", "postgres://example")
	t.Setenv("GATEWAY_READ_TIMEOUT", "not-a-duration")

	if _, err := config.Load(); err == nil {
		t.Fatal("expected invalid duration error")
	}
}

func TestLoadModeControlAndGateway(t *testing.T) {
	t.Setenv("POSTGRES_DSN", "postgres://example")

	t.Setenv("CLEARANCE_MODE", "control")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Mode != config.ModeControl {
		t.Fatalf("Mode = %q, want control", cfg.Mode)
	}

	t.Setenv("CLEARANCE_MODE", "gateway")
	t.Setenv("GATEWAY_PROXY_LISTEN_ADDR", ":9091")
	cfg, err = config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Mode != config.ModeGateway {
		t.Fatalf("Mode = %q, want gateway", cfg.Mode)
	}
	if cfg.GatewayListenAddr != ":9091" {
		t.Fatalf("GatewayListenAddr = %q, want :9091", cfg.GatewayListenAddr)
	}
}

func TestLoadRejectsInvalidMode(t *testing.T) {
	t.Setenv("POSTGRES_DSN", "postgres://example")
	t.Setenv("CLEARANCE_MODE", "bogus")

	if _, err := config.Load(); err == nil {
		t.Fatal("expected invalid CLEARANCE_MODE error")
	}
}

// A half-configured TLS keypair must be rejected rather than silently falling
// back to plaintext - the failure mode being guarded against is a deployment
// that believes it is encrypted and is not.
func TestTLSKeypairMustBeCompleteOrAbsent(t *testing.T) {
	t.Setenv("POSTGRES_DSN", "postgres://x/y")

	t.Setenv("CLEARANCE_TLS_CERT_FILE", "/tmp/cert.pem")
	t.Setenv("CLEARANCE_TLS_KEY_FILE", "")
	if _, err := config.Load(); err == nil {
		t.Fatal("a cert without a key was accepted")
	}

	t.Setenv("CLEARANCE_TLS_CERT_FILE", "")
	t.Setenv("CLEARANCE_TLS_KEY_FILE", "/tmp/key.pem")
	if _, err := config.Load(); err == nil {
		t.Fatal("a key without a cert was accepted")
	}

	// Neither is the normal local case and must remain valid.
	t.Setenv("CLEARANCE_TLS_CERT_FILE", "")
	t.Setenv("CLEARANCE_TLS_KEY_FILE", "")
	if _, err := config.Load(); err != nil {
		t.Fatalf("omitting TLS entirely should be valid: %v", err)
	}
}

func TestAuthModeValidation(t *testing.T) {
	t.Setenv("POSTGRES_DSN", "postgres://x/y")

	t.Setenv("CLEARANCE_AUTH_MODE", "oidc")
	t.Setenv("OIDC_ISSUER_URL", "")
	if _, err := config.Load(); err == nil {
		t.Fatal("oidc mode without an issuer was accepted")
	}

	t.Setenv("OIDC_ISSUER_URL", "https://idp.example")
	t.Setenv("OIDC_CLIENT_ID", "")
	t.Setenv("OIDC_AUDIENCE", "")
	if _, err := config.Load(); err == nil {
		t.Fatal("oidc mode without a client id or audience was accepted")
	}

	t.Setenv("OIDC_CLIENT_ID", "clearance")
	if _, err := config.Load(); err != nil {
		t.Fatalf("valid oidc config rejected: %v", err)
	}

	t.Setenv("CLEARANCE_AUTH_MODE", "disabled")
	if _, err := config.Load(); err == nil {
		t.Fatal("an unrecognised auth mode was accepted")
	}
}

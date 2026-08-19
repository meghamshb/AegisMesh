package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

const (
	defaultListenAddr    = ":8080"
	defaultServiceName   = "policy-gateway"
	defaultServiceVer    = "0.1.0-phase0"
	defaultPostgresDSN   = "postgres://hermes:hermes@postgres:5432/hermes_policy?sslmode=disable"
	defaultReadTimeout   = 15 * time.Second
	defaultWriteTimeout  = 15 * time.Second
	defaultIdleTimeout   = 60 * time.Second
	defaultShutdownGrace = 10 * time.Second
)

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
	proxyEnabled, err := boolEnv("GATEWAY_PROXY_ENABLED", false)
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
	}

	if cfg.PostgresDSN == "" {
		return Config{}, fmt.Errorf("POSTGRES_DSN must not be empty")
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

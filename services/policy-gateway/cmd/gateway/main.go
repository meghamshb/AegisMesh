package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/app"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/auth"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/config"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/fleet"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/policycache"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("load config", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := store.NewPostgres(ctx, cfg.PostgresDSN)
	if err != nil {
		logger.Error("connect postgres", "error", err)
		os.Exit(1)
	}
	defer st.Close()

	waitCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := app.WaitForStore(waitCtx, st, logger); err != nil {
		logger.Error("postgres not ready", "error", err)
		os.Exit(1)
	}

	// Fleet mode (Phases 5.9-5.10): a gateway process configured with a
	// control plane URL fails closed at cold start if it cannot load an
	// initial policy snapshot - it must never begin proxying traffic against
	// unknown policy - and from 5.10 it *decides* against that snapshot
	// rather than querying Postgres, so one central rule change reaches every
	// gateway on the next refresh without restarting anything.
	var application *app.App
	distributed := cfg.Mode == config.ModeGateway && cfg.ControlPlaneURL != ""

	if distributed {
		// TLS seam (Phase 5.11.1). The HTTP clients in policycache,
		// remoteidentity, and fleet all use Go's default transport, which
		// verifies certificates - there is no InsecureSkipVerify anywhere in
		// this codebase, and none should be added. A plaintext control-plane
		// URL is a local-Compose convenience only: over a real network it
		// exposes the gateway credential and every policy snapshot in transit.
		if !strings.HasPrefix(strings.ToLower(cfg.ControlPlaneURL), "https://") {
			logger.Warn("control plane URL is not HTTPS; acceptable only on a private development network",
				"control_url_scheme", schemeOf(cfg.ControlPlaneURL),
			)
		}

		cache := policycache.New(
			policycache.NewHTTPFetcher(cfg.ControlPlaneURL, cfg.GatewayToken),
			cfg.PolicyMaxStale,
			logger,
		)
		if err := cache.Start(ctx, cfg.PolicyRefreshInterval); err != nil {
			logger.Error("policy snapshot unavailable at startup, failing closed", "error", err)
			os.Exit(1)
		}
		logger.Info("policy snapshot loaded",
			"health", cache.Health(),
			"refresh_interval", cfg.PolicyRefreshInterval,
		)

		application = app.NewDistributed(cfg, logger, st, cache)

		// Fleet visibility. Reporting only: a gateway that cannot reach the
		// control plane keeps enforcing its last-known-good snapshot and
		// simply goes stale in the Gateways tab, so identity failures here
		// are logged rather than fatal.
		reporter := fleet.NewReporter(
			cfg.ControlPlaneURL, cfg.GatewayToken, cfg.ServiceVersion,
			cache, application.AgentCounter(), logger,
		)
		if err := reporter.Identify(ctx); err != nil {
			logger.Warn("could not resolve gateway identity at startup, will retry on heartbeat", "error", err)
		} else {
			logger.Info("gateway identity resolved", "gateway_id", reporter.GatewayID(), "name", reporter.Name())
		}
		reporter.Start(ctx, cfg.HeartbeatInterval)
	} else {
		application = app.New(cfg, logger, st)
	}

	// Control-plane authentication (Phase 5.13). The data plane is untouched:
	// agent credentials remain an entirely separate trust domain and never
	// pass through this resolver.
	if serving := cfg.Mode == config.ModeAll || cfg.Mode == config.ModeControl; serving {
		if err := configureControlPlaneAuth(ctx, cfg, application, st, logger); err != nil {
			logger.Error("configure control-plane authentication", "error", err)
			os.Exit(1)
		}
	}

	addr, handler := selectListener(cfg, application)
	httpServer := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	go func() {
		logger.Info("policy gateway listening",
			"mode", cfg.Mode,
			"addr", addr,
			"version", cfg.ServiceVersion,
			"proxy_enabled", cfg.ProxyEnabled,
		)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http server stopped", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
}

// selectListener picks which HTTP surface(s) this process serves, and on
// which address, based on CLEARANCE_MODE (Phase 5.8). "all" preserves the
// exact pre-5.8 single-listener behavior.
func selectListener(cfg config.Config, application *app.App) (addr string, handler http.Handler) {
	switch cfg.Mode {
	case config.ModeControl:
		return cfg.ListenAddr, application.ControlHandler()
	case config.ModeGateway:
		return cfg.GatewayListenAddr, application.ProxyHandler()
	default:
		return cfg.ListenAddr, application.Handler()
	}
}

// schemeOf reports a URL's scheme for logging, without echoing the URL itself
// (which may carry host detail an operator would rather not have in logs).
func schemeOf(raw string) string {
	if i := strings.Index(raw, "://"); i > 0 {
		return strings.ToLower(raw[:i])
	}
	return "none"
}

// configureControlPlaneAuth wires up whichever authentication mode is
// configured, and makes the weaker one impossible to run by accident.
func configureControlPlaneAuth(
	ctx context.Context,
	cfg config.Config,
	application *app.App,
	st store.Store,
	logger *slog.Logger,
) error {
	if cfg.AuthMode != config.AuthModeOIDC {
		// §5.13.4: dev-token mode must announce itself. A shared static secret
		// is a development affordance, not authentication - it cannot identify
		// who acted, so every audit entry collapses to one synthetic admin.
		// Silence here is how such a mode ends up in production.
		logger.Warn("CONTROL PLANE IS IN DEV-TOKEN MODE - not suitable for production",
			"auth_mode", cfg.AuthMode,
			"reason", "a shared static token cannot attribute actions to a person",
			"fix", "set CLEARANCE_AUTH_MODE=oidc with OIDC_ISSUER_URL and OIDC_CLIENT_ID",
		)
		if cfg.AdminToken == "" {
			logger.Warn("GATEWAY_ADMIN_TOKEN is empty - the control plane is UNAUTHENTICATED",
				"impact", "anyone who can reach this listener can approve egress and mint agent credentials",
			)
		}
		return nil
	}

	verifier, err := auth.NewOIDCVerifier(ctx, cfg.OIDCIssuerURL, cfg.OIDCClientID, cfg.OIDCAudience)
	if err != nil {
		return err
	}

	// Just-in-time linking binds a first login to an operator-created account.
	// It never creates accounts, so role assignment stays a deliberate act.
	application.SetPrincipalResolver(auth.NewResolver(verifier, st, true))

	logger.Info("control-plane authentication configured",
		"auth_mode", cfg.AuthMode,
		"issuer", cfg.OIDCIssuerURL,
	)
	return nil
}

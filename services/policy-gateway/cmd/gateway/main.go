package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/app"
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

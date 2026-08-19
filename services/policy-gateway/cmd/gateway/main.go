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

	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/app"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/config"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/store"
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

	application := app.New(cfg, logger, st)
	httpServer := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      application.Handler(),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	go func() {
		logger.Info("policy gateway listening",
			"addr", cfg.ListenAddr,
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

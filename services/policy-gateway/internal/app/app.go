package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/api"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/config"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/proxy"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/service"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/store"
)

type App struct {
	cfg    config.Config
	logger *slog.Logger
	proxy  *proxy.Handler
	api    *api.Server
}

func New(cfg config.Config, logger *slog.Logger, st store.Store) *App {
	egress := service.NewEgress(st)
	return &App{
		cfg:    cfg,
		logger: logger,
		proxy:  proxy.New(cfg.ProxyEnabled),
		api:    api.New(cfg, logger, st, egress),
	}
}

func (a *App) Handler() http.Handler {
	return a.withMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if proxy.IsProxyRequest(r) {
			a.proxy.ServeHTTP(w, r)
			return
		}
		a.api.Handler().ServeHTTP(w, r)
	}))
}

func WaitForStore(ctx context.Context, st store.Store, logger *slog.Logger) error {
	backoff := time.Second
	for {
		if err := st.Ping(ctx); err == nil {
			return nil
		} else if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			logger.Warn("waiting for postgres", "error", err, "retry_in", backoff)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}

		if backoff < 10*time.Second {
			backoff *= 2
		}
	}
}

func (a *App) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		a.logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(statusCode int) {
	r.status = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

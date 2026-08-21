package app

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/api"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/config"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/identity"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/policy"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/proxy"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/service"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
)

type App struct {
	cfg    config.Config
	logger *slog.Logger
	proxy  *proxy.Handler
	api    *api.Server
}

// New builds the single-process App: policy decisions come from a direct SQL
// query, exactly as before Phase 5.10. This is CLEARANCE_MODE=all.
func New(cfg config.Config, logger *slog.Logger, st store.Store) *App {
	return newApp(cfg, logger, st, policy.NewRuleEngine(st))
}

// NewDistributed builds a fleet gateway (Phase 5.10): policy decisions come
// from the centrally managed snapshot in `snapshots`, so a rule created once
// in the control plane reaches every gateway on its next refresh without a
// restart. Request-history state (standing denies, approve-once grants) and
// egress/audit persistence still go through st.
func NewDistributed(cfg config.Config, logger *slog.Logger, st store.Store, snapshots policy.SnapshotProvider) *App {
	return newApp(cfg, logger, st, policy.NewSnapshotRuleEngine(snapshots, st))
}

func newApp(cfg config.Config, logger *slog.Logger, st store.Store, engine policy.Engine) *App {
	egress := service.NewEgress(st, engine)
	identitySvc := identity.NewService(st)
	return &App{
		cfg:    cfg,
		logger: logger,
		proxy:  proxy.NewHandler(cfg.ProxyEnabled, cfg, egress, identitySvc, logger),
		api:    api.New(cfg, logger, st, egress, identitySvc),
	}
}

// AgentCounter exposes the data-plane handler's recently-seen-agent counter so
// the fleet heartbeat can report it. Implements fleet.AgentCounter.
func (a *App) AgentCounter() *proxy.Handler { return a.proxy }

// Handler serves both the control-plane API and the data-plane proxy on one
// listener, dispatching by request shape. This is CLEARANCE_MODE=all - the
// existing single-process monolith, unchanged from before Phase 5.8.
func (a *App) Handler() http.Handler {
	return a.withMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if proxy.IsProxyRequest(r) {
			a.proxy.ServeHTTP(w, r)
			return
		}
		a.api.Handler().ServeHTTP(w, r)
	}))
}

// ControlHandler serves only the control plane: users/agents/rules/requests/
// audit management plus the embedded admin UI. No proxy/CONNECT forwarding
// lives behind this handler at all (CLEARANCE_MODE=control).
func (a *App) ControlHandler() http.Handler {
	return a.withMiddleware(a.api.Handler())
}

// ProxyHandler serves the data-plane egress proxy, plus a liveness endpoint.
// No control-plane route (users/agents/rules/requests/audit/UI) is reachable
// through this handler (CLEARANCE_MODE=gateway) - satisfies "admin APIs are
// not exposed on the gateway proxy listener" without needing a second
// admin-token check.
//
// GET /health is the one exception, and it is not an admin API: a container
// healthcheck, load balancer, or orchestrator has to be able to ask a gateway
// whether it is alive, and health is already unauthenticated on the control
// plane. Without it a gateway-mode process answers 400 ("not a proxy request")
// to every probe, so anything gated on its health - including the agent
// container that is supposed to route through it - never starts.
//
// The dispatch below is the same shape as Handler(): only a *non-proxy*
// request for /health is served locally. A proxied request for
// http://somewhere/health still has a URL host, so it is forwarded and
// evaluated like any other egress.
func (a *App) ProxyHandler() http.Handler {
	return a.withMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !proxy.IsProxyRequest(r) && r.Method == http.MethodGet && r.URL.Path == "/health" {
			a.api.HealthHandler().ServeHTTP(w, r)
			return
		}
		a.proxy.ServeHTTP(w, r)
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
			"host", r.Host,
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

func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := r.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, errors.New("response writer does not support hijacking")
}

func (r *statusRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

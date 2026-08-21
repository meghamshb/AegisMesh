package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/config"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/identity"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/policy"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/remoteidentity"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/service"
)

// remoteAgentAuthenticator is satisfied by *remoteidentity.CachedClient. A
// narrow local interface keeps this package's tests free of a real HTTP
// client.
type remoteAgentAuthenticator interface {
	Authenticate(ctx context.Context, tokenHash string) (config.AgentIdentity, error)
}

type Handler struct {
	enabled               bool
	authMode              string
	identity              config.AgentIdentity
	allowIdentityOverride bool
	agentIDHeader         string
	userIDHeader          string
	egress                *service.EgressService
	identitySvc           *identity.Service
	remoteAgentAuth       remoteAgentAuthenticator
	logger                *slog.Logger
	transport             *http.Transport
	guard                 *UpstreamGuard

	// recentAgents tracks when each agent was last served, backing the
	// Gateways tab's "agents recently seen" column (Phase 5.10). It is
	// observability only - nothing here gates a request.
	recentAgentsMu sync.Mutex
	recentAgents   map[string]time.Time
}

// recentAgentWindow is how far back "recently seen" looks. A rolling window
// rather than a drain-on-read counter: heartbeats are frequent, so draining
// would report 0 for every beat that happened to follow a quiet second, making
// a busy gateway look idle.
const recentAgentWindow = 5 * time.Minute

// noteAgentSeen records that an agent was served just now.
func (h *Handler) noteAgentSeen(agentID string) {
	if agentID == "" {
		return
	}
	h.recentAgentsMu.Lock()
	defer h.recentAgentsMu.Unlock()
	if h.recentAgents == nil {
		h.recentAgents = map[string]time.Time{}
	}
	h.recentAgents[agentID] = time.Now()
}

// DrainRecentAgentCount returns the number of distinct agents served within the
// trailing window, evicting anything older. Implements fleet.AgentCounter.
func (h *Handler) DrainRecentAgentCount() int {
	h.recentAgentsMu.Lock()
	defer h.recentAgentsMu.Unlock()
	cutoff := time.Now().Add(-recentAgentWindow)
	for id, seen := range h.recentAgents {
		if seen.Before(cutoff) {
			delete(h.recentAgents, id)
		}
	}
	return len(h.recentAgents)
}

func NewHandler(
	enabled bool,
	cfg config.Config,
	egress *service.EgressService,
	identitySvc *identity.Service,
	logger *slog.Logger,
) *Handler {
	var remoteAuth remoteAgentAuthenticator
	if cfg.Mode == config.ModeGateway && cfg.ControlPlaneURL != "" {
		remoteAuth = remoteidentity.NewCachedClient(
			remoteidentity.NewClient(cfg.ControlPlaneURL, cfg.GatewayToken),
			cfg.AgentIdentityCacheTTL,
		)
	}
	// Proxied agent traffic must never reach the control plane, even though
	// this same process talks to it for policy sync (Phase 5.11.7).
	guard := NewUpstreamGuard(HostFromURL(cfg.ControlPlaneURL))

	return &Handler{
		guard:                 guard,
		enabled:               enabled,
		authMode:              cfg.AgentAuthMode,
		identity:              cfg.Identity,
		allowIdentityOverride: cfg.AllowIdentityOverride,
		agentIDHeader:         cfg.AgentIDHeader,
		userIDHeader:          cfg.UserIDHeader,
		egress:                egress,
		identitySvc:           identitySvc,
		remoteAgentAuth:       remoteAuth,
		logger:                logger,
		transport: &http.Transport{
			Proxy: nil,
			// Dial through the guard so the address that gets connected to is
			// the same one that was validated. A plain dialer would resolve
			// again here, reopening the DNS-rebinding window that IsBlocked
			// cannot close on its own.
			DialContext:           guard.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.enabled {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "egress proxy disabled",
		})
		return
	}

	parsed, err := ParseRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if blocked, reason := h.guard.IsBlocked(parsed.Host); blocked {
		h.logger.Warn("blocked internal upstream",
			"host", parsed.Host,
			"port", parsed.Port,
			"reason", reason,
		)
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":  "egress to internal destination blocked",
			"detail": reason,
		})
		return
	}

	reqIdentity, err := h.resolveIdentity(r)
	if err != nil {
		h.writeAuthError(w, err)
		return
	}

	decision, recorded, err := h.egress.RecordOutbound(r.Context(), reqIdentity, policy.Request{
		Method: parsed.Method,
		Host:   parsed.Host,
		Port:   parsed.Port,
		Path:   parsed.Path,
		Scheme: parsed.Scheme,
	})
	if err != nil {
		h.logger.Error("record outbound request", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to evaluate egress policy"})
		return
	}

	h.logger.Info("egress decision",
		"decision", decision,
		"request_id", recorded.ID,
		"host", parsed.Host,
		"method", parsed.Method,
		"path", parsed.Path,
	)

	switch decision {
	case policy.DecisionAllow:
		h.forward(w, r, parsed)
	case policy.DecisionDeny, policy.DecisionPending:
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":      "egress blocked pending approval",
			"request_id": recorded.ID,
			"status":     string(recorded.Status),
		})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unknown policy decision"})
	}
}

// resolveIdentity derives the trusted org/user/agent identity for a proxied
// request. In "static" mode it reproduces the pre-5.4 behavior exactly
// (including the identity-override headers, if enabled). In "token" mode,
// identity comes only from a valid Proxy-Authorization agent credential;
// identity-override headers are never honored, so a valid Agent A token can
// never be used to claim Agent B's identity.
func (h *Handler) resolveIdentity(r *http.Request) (config.AgentIdentity, error) {
	ident, err := h.resolveIdentityInner(r)
	if err == nil {
		h.noteAgentSeen(ident.AgentID)
	}
	return ident, err
}

func (h *Handler) resolveIdentityInner(r *http.Request) (config.AgentIdentity, error) {
	if h.authMode == config.AgentAuthModeToken {
		return h.resolveTokenIdentity(r)
	}
	return h.resolveStaticIdentity(r), nil
}

func (h *Handler) resolveStaticIdentity(r *http.Request) config.AgentIdentity {
	result := h.identity
	if !h.allowIdentityOverride {
		return result
	}
	if agentID := strings.TrimSpace(r.Header.Get(h.agentIDHeader)); agentID != "" {
		result.AgentID = agentID
	}
	if userID := strings.TrimSpace(r.Header.Get(h.userIDHeader)); userID != "" {
		result.UserID = userID
	}
	return result
}

func (h *Handler) resolveTokenIdentity(r *http.Request) (config.AgentIdentity, error) {
	token, ok := extractProxyToken(r)
	if !ok {
		return config.AgentIdentity{}, identity.ErrInvalidToken
	}

	// Fleet mode (Phase 5.9.10): resolve identity via the control plane's
	// internal API instead of a direct DB lookup, hashing locally so the
	// plaintext token never crosses the network.
	if h.remoteAgentAuth != nil {
		return h.remoteAgentAuth.Authenticate(r.Context(), identity.HashAgentToken(token))
	}

	authed, err := h.identitySvc.AuthenticateAgentToken(r.Context(), token)
	if err != nil {
		return config.AgentIdentity{}, err
	}

	return config.AgentIdentity{
		OrgID:   authed.OrgID,
		UserID:  authed.OwnerUserID,
		AgentID: authed.AgentID,
	}, nil
}

// extractProxyToken reads the agent credential from Proxy-Authorization,
// supporting both "Bearer <token>" and "Basic <base64(agent:<token>)>".
func extractProxyToken(r *http.Request) (string, bool) {
	header := strings.TrimSpace(r.Header.Get("Proxy-Authorization"))
	if header == "" {
		return "", false
	}

	scheme, value, found := strings.Cut(header, " ")
	if !found {
		return "", false
	}
	value = strings.TrimSpace(value)

	switch strings.ToLower(scheme) {
	case "bearer":
		if value == "" {
			return "", false
		}
		return value, true
	case "basic":
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return "", false
		}
		_, password, found := strings.Cut(string(decoded), ":")
		if !found || password == "" {
			return "", false
		}
		return password, true
	default:
		return "", false
	}
}

// writeAuthError maps a proxy identity error to the correct HTTP status.
// A missing/invalid/revoked credential is a 407 (the client must supply a
// valid proxy credential); a revoked agent or suspended org is a 403
// (the credential is well-formed but no longer authorized). Neither case
// creates a pending egress_requests row.
func (h *Handler) writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, identity.ErrInvalidToken), errors.Is(err, identity.ErrCredentialRevoked):
		w.Header().Set("Proxy-Authenticate", `Bearer realm="clearance-gateway"`)
		writeJSON(w, http.StatusProxyAuthRequired, map[string]string{"error": "valid agent credential required"})
	case errors.Is(err, identity.ErrAgentRevoked), errors.Is(err, identity.ErrOrgSuspended), errors.Is(err, identity.ErrOwnerDisabled):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
	default:
		// Anything else is an infrastructure failure rather than a verdict on
		// the credential - most often a distributed gateway unable to reach
		// the control plane to resolve identity.
		//
		// This is reported as 503, not 500. The behaviour is already correct
		// (no identity means no egress, so the request is refused), but a 500
		// reads as "the gateway is broken" when what actually happened is "the
		// gateway deliberately refused because it could not verify who you
		// are". 503 says that, and tells a client the condition is temporary
		// and retryable. Phase 5.12's evaluation harness relies on this
		// distinction too: it must be able to tell a fail-closed refusal from
		// a response that came back from the destination.
		h.logger.Error("resolve proxy identity", "error", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "cannot verify agent identity; refusing egress",
		})
	}
}

func (h *Handler) forward(w http.ResponseWriter, r *http.Request, parsed ParsedRequest) {
	if r.Method == http.MethodConnect {
		h.forwardCONNECT(w, r)
		return
	}
	h.forwardHTTP(w, r)
}

func (h *Handler) forwardHTTP(w http.ResponseWriter, r *http.Request) {
	outReq := r.Clone(r.Context())
	// The Clearance credential authenticates the caller to this gateway; it
	// must never reach the destination.
	outReq.Header.Del("Proxy-Authorization")
	outReq.Header.Del("Proxy-Connection")
	resp, err := h.transport.RoundTrip(outReq)
	if err != nil {
		var blocked ErrBlockedUpstream
		if errors.As(err, &blocked) {
			// The name passed the pre-flight check but resolved to an internal
			// address at dial time. Report it as the hard denial it is, so it
			// is not mistaken for an upstream being down.
			h.logger.Warn("blocked upstream at dial time",
				"host", blocked.Host, "reason", blocked.Reason)
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error":  "egress to internal destination blocked",
				"detail": blocked.Reason,
			})
			return
		}
		h.logger.Error("forward http request", "error", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream request failed"})
		return
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		h.logger.Error("copy upstream response", "error", err)
	}
}

func (h *Handler) forwardCONNECT(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "connect hijack unsupported"})
		return
	}

	// CONNECT gets the same treatment. It is the easier target of the two:
	// once the tunnel is open Clearance sees only bytes, so a rebound address
	// here would never be noticed again.
	dialCtx, cancelDial := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancelDial()

	upstream, err := h.guard.DialContext(dialCtx, "tcp", r.Host)
	if err != nil {
		var blocked ErrBlockedUpstream
		if errors.As(err, &blocked) {
			h.logger.Warn("blocked CONNECT upstream at dial time",
				"host", blocked.Host, "reason", blocked.Reason)
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error":  "egress to internal destination blocked",
				"detail": blocked.Reason,
			})
			return
		}
		h.logger.Error("connect upstream", "error", err, "host", r.Host)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream connect failed"})
		return
	}
	defer upstream.Close()

	clientConn, bufRW, err := hijacker.Hijack()
	if err != nil {
		h.logger.Error("hijack client connection", "error", err)
		return
	}
	defer clientConn.Close()

	if _, err := bufRW.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		h.logger.Error("write connect established", "error", err)
		return
	}
	if err := bufRW.Flush(); err != nil {
		h.logger.Error("flush connect established", "error", err)
		return
	}

	errCh := make(chan error, 2)
	go func() { _, err := io.Copy(upstream, bufRW); errCh <- err }()
	go func() { _, err := io.Copy(clientConn, upstream); errCh <- err }()
	<-errCh
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

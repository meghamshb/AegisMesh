package proxy

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/config"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/policy"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/service"
)

type Handler struct {
	enabled   bool
	identity  config.AgentIdentity
	egress    *service.EgressService
	logger    *slog.Logger
	transport *http.Transport
}

func NewHandler(
	enabled bool,
	identity config.AgentIdentity,
	egress *service.EgressService,
	logger *slog.Logger,
) *Handler {
	return &Handler{
		enabled:  enabled,
		identity: identity,
		egress:   egress,
		logger:   logger,
		transport: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
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

	decision, recorded, err := h.egress.RecordOutbound(r.Context(), h.identity, policy.Request{
		OrgID:  h.identity.OrgID,
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

func (h *Handler) forward(w http.ResponseWriter, r *http.Request, parsed ParsedRequest) {
	if r.Method == http.MethodConnect {
		h.forwardCONNECT(w, r)
		return
	}
	h.forwardHTTP(w, r)
}

func (h *Handler) forwardHTTP(w http.ResponseWriter, r *http.Request) {
	outReq := r.Clone(r.Context())
	resp, err := h.transport.RoundTrip(outReq)
	if err != nil {
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

	upstream, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
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

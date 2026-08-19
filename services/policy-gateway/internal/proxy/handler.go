package proxy

import (
	"encoding/json"
	"net/http"
)

type Handler struct {
	enabled bool
}

func New(enabled bool) *Handler {
	return &Handler{enabled: enabled}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.enabled {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "egress proxy disabled in phase 0; enable with GATEWAY_PROXY_ENABLED=true in phase 1",
		})
		return
	}

	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "egress proxy not implemented yet",
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func IsProxyRequest(r *http.Request) bool {
	if r.Method == http.MethodConnect {
		return true
	}
	if r.URL.Host != "" {
		return true
	}
	if r.Header.Get("Proxy-Connection") != "" {
		return true
	}
	return false
}

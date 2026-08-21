package api

import (
	"net/http"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/config"
)

// handleAuthConfig tells a client how to authenticate against this deployment.
//
// It is deliberately unauthenticated: the console has to know whether to show
// a dev-token field or send users to an identity provider *before* it holds
// any credential. Everything returned is public configuration that a browser
// performing an OIDC flow would need anyway - issuer and client id are not
// secrets. No token, audience secret, or admin credential is exposed.
func (s *Server) handleAuthConfig(w http.ResponseWriter, r *http.Request) {
	payload := map[string]any{
		"mode": s.effectiveAuthMode(),
	}

	if s.effectiveAuthMode() == config.AuthModeOIDC {
		payload["issuer"] = s.cfg.OIDCIssuerURL
		payload["client_id"] = s.cfg.OIDCClientID
	} else {
		// Surfaced so the console can warn rather than silently present a
		// shared-secret login as though it were real authentication.
		payload["dev_token_required"] = s.cfg.AdminToken != ""
	}

	s.writeJSON(w, http.StatusOK, payload)
}

// effectiveAuthMode reports the mode actually being enforced.
//
// requirePrincipal treats anything that is not "oidc" as dev-token, so this
// must agree with it: reporting a mode the server does not actually apply
// would be worse than reporting none at all. config.Load rejects unknown
// values, so in a real process this only normalizes the zero value.
func (s *Server) effectiveAuthMode() string {
	if s.cfg.AuthMode == config.AuthModeOIDC {
		return config.AuthModeOIDC
	}
	return config.AuthModeDevToken
}

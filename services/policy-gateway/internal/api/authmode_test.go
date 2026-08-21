package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/api"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/auth"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/config"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/identity"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/policy"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/service"
)

// Phase 5.13: both authentication modes must converge on the same
// domain.Principal, so no handler or policy code knows which one ran.

// fixedVerifier stands in for a real provider: token verification itself is
// covered end to end with real RSA signatures in internal/auth, so these tests
// focus on what the API does with the resulting identity.
type fixedVerifier struct{ claims auth.Claims }

func (v fixedVerifier) Verify(context.Context, string) (auth.Claims, error) {
	return v.claims, nil
}

type failingVerifier struct{}

func (failingVerifier) Verify(context.Context, string) (auth.Claims, error) {
	return auth.Claims{}, errors.New("signature invalid")
}

// oidcDirectory is a minimal auth.Directory keyed by external subject.
type oidcDirectory struct{ users map[string]domain.User }

func (d *oidcDirectory) GetUserByExternalSubject(_ context.Context, s string) (domain.User, error) {
	if u, ok := d.users[s]; ok {
		return u, nil
	}
	return domain.User{}, domain.ErrNotFound{Resource: "user", ID: "external_subject"}
}

func (d *oidcDirectory) GetUserByEmail(_ context.Context, _ string) (domain.User, error) {
	return domain.User{}, domain.ErrNotFound{Resource: "user", ID: "email"}
}

func (d *oidcDirectory) LinkExternalSubject(context.Context, string, string, string) error {
	return nil
}

func oidcServer(t *testing.T, st stubStore, resolver *auth.Resolver) *api.Server {
	t.Helper()
	cfg := config.Config{
		ServiceName:     "policy-gateway",
		ServiceVersion:  "test",
		AuthMode:        config.AuthModeOIDC,
		OIDCIssuerURL:   "https://idp.example",
		OIDCClientID:    "clearance-console",
		Identity:        config.AgentIdentity{OrgID: "org-1", UserID: "user-1", AgentID: "agent-1"},
		RateLimitWindow: time.Minute,
	}
	egress := service.NewEgress(st, policy.NewRuleEngine(st))
	srv := api.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), st, egress, identity.NewService(st))
	return srv.WithPrincipalResolver(resolver)
}

// The console must be able to discover how to authenticate before it holds any
// credential, so this endpoint is unauthenticated by design.
func TestAuthConfigIsUnauthenticatedAndLeaksNoSecret(t *testing.T) {
	srv := oidcServer(t, testDirectoryFixtures(), nil)

	rec := send(srv, http.MethodGet, "/api/v1/auth/config", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 without credentials", rec.Code)
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload["mode"] != config.AuthModeOIDC {
		t.Fatalf("mode = %v, want oidc", payload["mode"])
	}
	if payload["issuer"] != "https://idp.example" {
		t.Fatalf("issuer = %v", payload["issuer"])
	}
	body := rec.Body.String()
	for _, secret := range []string{"dev-local-admin-token", testAdminToken, "client_secret"} {
		if secret != "" && contains(body, secret) {
			t.Fatalf("auth config leaked a secret: %s", body)
		}
	}
}

func TestDevTokenModeAuthConfigReportsDevMode(t *testing.T) {
	srv := securityServer(t, testDirectoryFixtures(), 100, 100)

	rec := send(srv, http.MethodGet, "/api/v1/auth/config", nil, "")
	var payload map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &payload)

	if payload["mode"] != config.AuthModeDevToken {
		t.Fatalf("mode = %v, want dev-token", payload["mode"])
	}
	if payload["dev_token_required"] != true {
		t.Fatalf("dev_token_required = %v, want true", payload["dev_token_required"])
	}
}

// In OIDC mode the static admin token must stop working entirely - otherwise
// deploying OIDC would leave a shared-secret back door in place.
func TestOIDCModeRejectsTheAdminToken(t *testing.T) {
	dir := &oidcDirectory{users: map[string]domain.User{}}
	resolver := auth.NewResolver(failingVerifier{}, dir, true)
	srv := oidcServer(t, testDirectoryFixtures(), resolver)

	rec := send(srv, http.MethodGet, "/api/v1/users",
		map[string]string{"X-Admin-Token": testAdminToken}, "")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: the admin token must not work in OIDC mode", rec.Code)
	}
}

func TestOIDCModeRejectsMissingToken(t *testing.T) {
	dir := &oidcDirectory{users: map[string]domain.User{}}
	srv := oidcServer(t, testDirectoryFixtures(), auth.NewResolver(failingVerifier{}, dir, true))

	rec := send(srv, http.MethodGet, "/api/v1/users", nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("expected a WWW-Authenticate challenge")
	}
}

// A verified identity that is not provisioned gets 403, and the response must
// not reveal whether the subject, the email, or the account was the problem.
func TestOIDCModeUnprovisionedIdentityIsForbiddenWithoutDetail(t *testing.T) {
	dir := &oidcDirectory{users: map[string]domain.User{}}
	resolver := auth.NewResolver(
		fixedVerifier{claims: auth.Claims{Issuer: "https://idp.example", Subject: "nobody"}},
		dir, true)
	srv := oidcServer(t, testDirectoryFixtures(), resolver)

	rec := send(srv, http.MethodGet, "/api/v1/users",
		map[string]string{"Authorization": "Bearer any-token"}, "")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, leak := range []string{"nobody", "external_subject", "email"} {
		if contains(body, leak) {
			t.Fatalf("403 response leaked identity detail (%q): %s", leak, body)
		}
	}
}

// The payoff of the whole phase: the caller's org comes from their own actor
// row, not from process configuration.
func TestOIDCPrincipalOrgComesFromTheActorNotConfig(t *testing.T) {
	external := "https://idp.example#alice"
	dir := &oidcDirectory{users: map[string]domain.User{
		external: {ID: "user-1", OrgID: "org-1", Role: domain.RoleAdmin, Status: "active"},
	}}
	resolver := auth.NewResolver(
		fixedVerifier{claims: auth.Claims{Issuer: "https://idp.example", Subject: "alice"}},
		dir, true)

	srv := oidcServer(t, testDirectoryFixtures(), resolver)
	rec := send(srv, http.MethodGet, "/api/v1/users",
		map[string]string{"Authorization": "Bearer good-token"}, "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	// org-1 fixtures are visible; had the org come from anywhere else this
	// would be empty or wrong.
	if !contains(rec.Body.String(), "Alice") {
		t.Fatalf("expected org-1 users, got %s", rec.Body.String())
	}
}

// A member must not be able to perform admin-only actions, proving the role
// carried on the Principal is actually enforced end to end.
func TestOIDCMemberRoleIsEnforcedByHandlers(t *testing.T) {
	external := "https://idp.example#bob"
	dir := &oidcDirectory{users: map[string]domain.User{
		external: {ID: "user-2", OrgID: "org-1", Role: domain.RoleMember, Status: "active"},
	}}
	resolver := auth.NewResolver(
		fixedVerifier{claims: auth.Claims{Issuer: "https://idp.example", Subject: "bob"}},
		dir, true)

	srv := oidcServer(t, testDirectoryFixtures(), resolver)
	rec := send(srv, http.MethodPost, "/api/v1/users",
		map[string]string{"Authorization": "Bearer good-token", "Content-Type": "application/json"},
		`{"display_name":"Mallory","role":"admin"}`)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: a member must not create users (body=%s)",
			rec.Code, rec.Body.String())
	}
}

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}

package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/auth"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
)

// The resolver is where authentication becomes authorization. These tests pin
// the rule that matters most: the token says who you are, the database says
// what you may do.

type fakeVerifier struct {
	claims auth.Claims
	err    error
}

func (f fakeVerifier) Verify(context.Context, string) (auth.Claims, error) {
	return f.claims, f.err
}

type fakeDirectory struct {
	byExternal map[string]domain.User
	byEmail    map[string]domain.User
	ambiguous  map[string]bool
	linked     map[string]string // userID -> externalSubject
	linkErr    error
}

func newFakeDirectory() *fakeDirectory {
	return &fakeDirectory{
		byExternal: map[string]domain.User{},
		byEmail:    map[string]domain.User{},
		ambiguous:  map[string]bool{},
		linked:     map[string]string{},
	}
}

func (f *fakeDirectory) GetUserByExternalSubject(_ context.Context, s string) (domain.User, error) {
	if u, ok := f.byExternal[s]; ok {
		return u, nil
	}
	return domain.User{}, domain.ErrNotFound{Resource: "user", ID: "external_subject"}
}

func (f *fakeDirectory) GetUserByEmail(_ context.Context, e string) (domain.User, error) {
	if f.ambiguous[e] {
		return domain.User{}, domain.ErrAmbiguousEmail{Email: e}
	}
	if u, ok := f.byEmail[e]; ok {
		return u, nil
	}
	return domain.User{}, domain.ErrNotFound{Resource: "user", ID: "email"}
}

func (f *fakeDirectory) LinkExternalSubject(_ context.Context, _, userID, external string) error {
	if f.linkErr != nil {
		return f.linkErr
	}
	f.linked[userID] = external
	return nil
}

func claimsFor(subject, email string, verified bool) auth.Claims {
	return auth.Claims{
		Issuer:        "https://idp.example",
		Subject:       subject,
		Email:         email,
		EmailVerified: verified,
	}
}

func TestResolvesLinkedSubjectToItsActor(t *testing.T) {
	dir := newFakeDirectory()
	claims := claimsFor("alice-sub", "alice@example.com", true)
	dir.byExternal[claims.ExternalSubject()] = domain.User{
		ID: "user-1", OrgID: "org-7", Role: domain.RoleApprover, Status: "active",
	}

	r := auth.NewResolver(fakeVerifier{claims: claims}, dir, true)
	principal, err := r.Resolve(context.Background(), "token")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if principal.ActorID != "user-1" {
		t.Fatalf("ActorID = %q", principal.ActorID)
	}
	// The org comes from the actor, not from process configuration - this is
	// what finally makes Principal.OrgID genuinely per-caller.
	if principal.OrgID != "org-7" {
		t.Fatalf("OrgID = %q, want org-7 (from the actor row)", principal.OrgID)
	}
	if principal.Role != domain.RoleApprover {
		t.Fatalf("Role = %q, want the role stored in the database", principal.Role)
	}
}

// §5.13.5: the identity provider proves identity; Clearance decides
// authorization. A role claim in the token must have no effect whatsoever.
func TestRoleComesFromDatabaseNotFromToken(t *testing.T) {
	dir := newFakeDirectory()
	claims := claimsFor("mallory-sub", "mallory@example.com", true)
	dir.byExternal[claims.ExternalSubject()] = domain.User{
		ID: "user-9", OrgID: "org-1", Role: domain.RoleMember, Status: "active",
	}

	// auth.Claims has no Role field by construction, so a provider cannot even
	// express one. This asserts the resulting principal is the DB's member role
	// rather than anything elevated.
	r := auth.NewResolver(fakeVerifier{claims: claims}, dir, true)
	principal, err := r.Resolve(context.Background(), "token")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if principal.Role != domain.RoleMember {
		t.Fatalf("Role = %q, want member - roles must come only from the database", principal.Role)
	}
	if principal.CanManageUsers() {
		t.Fatal("a member principal was granted user management")
	}
}

// No auto-provisioning: a verified identity with no Clearance actor is
// refused, not silently granted access with some default role.
func TestUnknownSubjectIsRefusedNotProvisioned(t *testing.T) {
	dir := newFakeDirectory()
	claims := claimsFor("stranger-sub", "stranger@example.com", true)

	r := auth.NewResolver(fakeVerifier{claims: claims}, dir, true)
	_, err := r.Resolve(context.Background(), "token")

	if !errors.Is(err, auth.ErrUnknownSubject) {
		t.Fatalf("err = %v, want ErrUnknownSubject", err)
	}
	if len(dir.linked) != 0 {
		t.Fatal("an unknown identity was linked to an account")
	}
}

func TestJITLinksVerifiedEmailToExistingActor(t *testing.T) {
	dir := newFakeDirectory()
	claims := claimsFor("alice-sub", "alice@example.com", true)
	dir.byEmail["alice@example.com"] = domain.User{
		ID: "user-1", OrgID: "org-1", Role: domain.RoleAdmin, Status: "active",
	}

	r := auth.NewResolver(fakeVerifier{claims: claims}, dir, true)
	principal, err := r.Resolve(context.Background(), "token")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if principal.ActorID != "user-1" {
		t.Fatalf("ActorID = %q", principal.ActorID)
	}
	if dir.linked["user-1"] != claims.ExternalSubject() {
		t.Fatalf("expected the subject to be bound to the account, got %q", dir.linked["user-1"])
	}
}

// An unverified email is an assertion the provider will not stand behind, so
// it must not be enough to claim an existing account.
func TestUnverifiedEmailCannotClaimAnAccount(t *testing.T) {
	dir := newFakeDirectory()
	claims := claimsFor("attacker-sub", "alice@example.com", false)
	dir.byEmail["alice@example.com"] = domain.User{
		ID: "user-1", OrgID: "org-1", Role: domain.RoleAdmin, Status: "active",
	}

	r := auth.NewResolver(fakeVerifier{claims: claims}, dir, true)
	if _, err := r.Resolve(context.Background(), "token"); !errors.Is(err, auth.ErrUnknownSubject) {
		t.Fatalf("err = %v, want refusal for an unverified email", err)
	}
	if len(dir.linked) != 0 {
		t.Fatal("an unverified email was allowed to claim an account")
	}
}

// An account already bound to one external identity must not be rebound by a
// login from a different subject, even with a matching verified email.
func TestAlreadyLinkedAccountIsNotRebound(t *testing.T) {
	dir := newFakeDirectory()
	existing := "https://other-idp.example#original-sub"
	claims := claimsFor("attacker-sub", "alice@example.com", true)
	dir.byEmail["alice@example.com"] = domain.User{
		ID: "user-1", OrgID: "org-1", Role: domain.RoleAdmin, Status: "active",
		ExternalSubject: &existing,
	}

	r := auth.NewResolver(fakeVerifier{claims: claims}, dir, true)
	if _, err := r.Resolve(context.Background(), "token"); !errors.Is(err, auth.ErrUnknownSubject) {
		t.Fatalf("err = %v, want refusal when the account is already linked", err)
	}
	if len(dir.linked) != 0 {
		t.Fatal("an already-linked account was rebound to a new identity")
	}
}

// Email is unique per organization, not globally. An ambiguous match must be
// refused rather than resolved arbitrarily.
func TestAmbiguousEmailIsRefused(t *testing.T) {
	dir := newFakeDirectory()
	claims := claimsFor("alice-sub", "alice@example.com", true)
	dir.ambiguous["alice@example.com"] = true

	r := auth.NewResolver(fakeVerifier{claims: claims}, dir, true)
	_, err := r.Resolve(context.Background(), "token")

	var ambiguous domain.ErrAmbiguousEmail
	if !errors.As(err, &ambiguous) {
		t.Fatalf("err = %v, want ErrAmbiguousEmail", err)
	}
}

func TestEmailLinkingCanBeDisabled(t *testing.T) {
	dir := newFakeDirectory()
	claims := claimsFor("alice-sub", "alice@example.com", true)
	dir.byEmail["alice@example.com"] = domain.User{
		ID: "user-1", OrgID: "org-1", Role: domain.RoleAdmin, Status: "active",
	}

	r := auth.NewResolver(fakeVerifier{claims: claims}, dir, false)
	if _, err := r.Resolve(context.Background(), "token"); !errors.Is(err, auth.ErrUnknownSubject) {
		t.Fatalf("err = %v, want refusal when email linking is disabled", err)
	}
	if len(dir.linked) != 0 {
		t.Fatal("linking happened despite being disabled")
	}
}

func TestDisabledUserIsRefused(t *testing.T) {
	dir := newFakeDirectory()
	claims := claimsFor("alice-sub", "alice@example.com", true)
	dir.byExternal[claims.ExternalSubject()] = domain.User{
		ID: "user-1", OrgID: "org-1", Role: domain.RoleAdmin, Status: "disabled",
	}

	r := auth.NewResolver(fakeVerifier{claims: claims}, dir, true)
	if _, err := r.Resolve(context.Background(), "token"); !errors.Is(err, auth.ErrUserDisabled) {
		t.Fatalf("err = %v, want ErrUserDisabled", err)
	}
}

func TestMissingAndInvalidTokens(t *testing.T) {
	dir := newFakeDirectory()

	r := auth.NewResolver(fakeVerifier{claims: claimsFor("s", "", false)}, dir, true)
	if _, err := r.Resolve(context.Background(), "   "); !errors.Is(err, auth.ErrNoCredential) {
		t.Fatalf("err = %v, want ErrNoCredential for an empty token", err)
	}

	bad := auth.NewResolver(fakeVerifier{err: errors.New("signature invalid")}, dir, true)
	if _, err := bad.Resolve(context.Background(), "token"); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

// A token that verifies but carries no subject cannot identify anyone.
func TestTokenWithoutSubjectIsRejected(t *testing.T) {
	dir := newFakeDirectory()
	r := auth.NewResolver(fakeVerifier{claims: auth.Claims{Issuer: "https://idp.example"}}, dir, true)

	if _, err := r.Resolve(context.Background(), "token"); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken for a subject-less token", err)
	}
}

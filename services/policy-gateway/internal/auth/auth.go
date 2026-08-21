// Package auth is the control-plane authentication seam (Phase 5.13).
//
// It separates two things that are easy to conflate:
//
//	Authentication  - who is calling. In OIDC mode this comes from a verified
//	                  JWT issued by an external identity provider.
//	Authorization   - what they may do. This always comes from Clearance's own
//	                  database, never from a token claim.
//
// That split is deliberate (§5.13.5). A provider can prove someone is
// alice@example.com; it cannot be allowed to decide that alice is an admin of
// this organization, because then anyone who controls a role claim controls
// Clearance. Roles live in actors.role and are set by an operator.
//
// This package deliberately contains no password handling of any kind. There
// is no registration, reset, verification, or credential storage for humans -
// identity is delegated. The only secrets Clearance stores are agent and
// gateway credentials, which are a separate trust domain entirely and never
// pass through here.
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
)

var (
	// ErrNoCredential means the request carried no bearer token at all.
	ErrNoCredential = errors.New("authentication required")
	// ErrInvalidToken means the token failed verification (signature, issuer,
	// audience, or expiry).
	ErrInvalidToken = errors.New("invalid or expired token")
	// ErrUnknownSubject means the token verified, but its subject is not
	// linked to any Clearance actor. Access is refused rather than
	// auto-provisioned: see Resolver.Resolve.
	ErrUnknownSubject = errors.New("authenticated identity is not provisioned in this Clearance deployment")
	// ErrUserDisabled means the actor exists but has been disabled.
	ErrUserDisabled = errors.New("user is disabled")
)

// Ambiguous-email refusals surface as domain.ErrAmbiguousEmail from the store
// and are passed through unwrapped, so callers can distinguish "this email
// identifies nobody" from "this email identifies more than one account" - the
// second is a provisioning mistake an operator needs to see.

// Claims is the identity a successfully verified token asserts. It is
// deliberately narrow: adding a Role field here would invite someone to trust
// it.
type Claims struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
}

// ExternalSubject is the stable key stored in actors.external_subject.
//
// The issuer is included because a bare subject is only unique *within* an
// issuer. Storing "alice-123" alone would let a second, attacker-controlled
// issuer mint a token with the same subject and take over the account.
func (c Claims) ExternalSubject() string {
	return c.Issuer + "#" + c.Subject
}

// TokenVerifier validates a raw bearer token and returns its claims. The OIDC
// implementation lives in oidc.go; tests supply their own.
type TokenVerifier interface {
	Verify(ctx context.Context, rawToken string) (Claims, error)
}

// Directory is the subset of the store this package needs to turn a verified
// identity into a Clearance actor.
//
// These lookups are intentionally not organization-scoped. They are the
// authentication hop that *produces* the caller's organization, exactly like
// ResolveAgentForAuth on the data-plane side - there is no caller org to
// filter by until they succeed. Every subsequent query is scoped to the org
// they return.
type Directory interface {
	GetUserByExternalSubject(ctx context.Context, externalSubject string) (domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (domain.User, error)
	LinkExternalSubject(ctx context.Context, orgID, userID, externalSubject string) error
}

// Resolver turns a verified token into a Principal.
type Resolver struct {
	verifier  TokenVerifier
	directory Directory
	// allowEmailLinking controls just-in-time linking of a verified email to
	// an existing, unlinked actor.
	allowEmailLinking bool
}

func NewResolver(verifier TokenVerifier, directory Directory, allowEmailLinking bool) *Resolver {
	return &Resolver{verifier: verifier, directory: directory, allowEmailLinking: allowEmailLinking}
}

// Resolve verifies rawToken and maps it to the Clearance actor it represents.
//
// It will link a verified email to an existing actor that has no external
// subject yet, but it will never *create* an actor. Auto-provisioning would
// mean anyone the identity provider will issue a token for silently gains
// access to this deployment, with whatever default role was chosen for them.
// Requiring an operator to create the user first keeps role assignment a
// deliberate act.
func (r *Resolver) Resolve(ctx context.Context, rawToken string) (domain.Principal, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return domain.Principal{}, ErrNoCredential
	}

	claims, err := r.verifier.Verify(ctx, rawToken)
	if err != nil {
		return domain.Principal{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return domain.Principal{}, fmt.Errorf("%w: token has no subject", ErrInvalidToken)
	}

	user, err := r.lookup(ctx, claims)
	if err != nil {
		return domain.Principal{}, err
	}
	if user.Status != "active" {
		return domain.Principal{}, fmt.Errorf("%w: %s", ErrUserDisabled, user.ID)
	}

	// Role and organization come from the database row, never from the token.
	return domain.Principal{
		ActorID: user.ID,
		OrgID:   user.OrgID,
		Role:    user.Role,
	}, nil
}

func (r *Resolver) lookup(ctx context.Context, claims Claims) (domain.User, error) {
	external := claims.ExternalSubject()

	user, err := r.directory.GetUserByExternalSubject(ctx, external)
	if err == nil {
		return user, nil
	}
	var notFound domain.ErrNotFound
	if !errors.As(err, &notFound) {
		return domain.User{}, fmt.Errorf("look up external subject: %w", err)
	}

	// Not linked yet. Fall back to a verified email, if that is permitted.
	if !r.allowEmailLinking {
		return domain.User{}, ErrUnknownSubject
	}
	email := strings.TrimSpace(strings.ToLower(claims.Email))
	if email == "" || !claims.EmailVerified {
		// An unverified email is an assertion the provider itself will not
		// stand behind, so it must not be enough to claim an account.
		return domain.User{}, ErrUnknownSubject
	}

	candidate, err := r.directory.GetUserByEmail(ctx, email)
	if err != nil {
		var ambiguous domain.ErrAmbiguousEmail
		if errors.As(err, &ambiguous) {
			return domain.User{}, err
		}
		if errors.As(err, &notFound) {
			return domain.User{}, ErrUnknownSubject
		}
		return domain.User{}, fmt.Errorf("look up user by email: %w", err)
	}
	if candidate.ExternalSubject != nil && *candidate.ExternalSubject != "" {
		// Already bound to a different external identity. Rebinding here would
		// let a second provider hijack an existing account.
		return domain.User{}, ErrUnknownSubject
	}

	if err := r.directory.LinkExternalSubject(ctx, candidate.OrgID, candidate.ID, external); err != nil {
		return domain.User{}, fmt.Errorf("link external subject: %w", err)
	}
	candidate.ExternalSubject = &external
	return candidate, nil
}

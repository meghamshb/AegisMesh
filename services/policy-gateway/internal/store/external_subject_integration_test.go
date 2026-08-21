//go:build integration

package store_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
)

// Phase 5.13 identity linking, against real Postgres. The constraints being
// checked here are enforced by the database, so a unit test with a fake store
// would prove nothing about them.

func uniqueSubject(prefix string) string {
	return fmt.Sprintf("https://idp.test#%s-%d", prefix, time.Now().UnixNano())
}

func TestLinkAndResolveExternalSubject(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()

	email := fmt.Sprintf("link-%d@example.com", time.Now().UnixNano())
	user, err := pg.CreateUser(ctx, store.CreateUserInput{
		OrgID: seededOrgID, DisplayName: "Link Target", Email: &email, Role: domain.RoleApprover,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	subject := uniqueSubject("alice")
	if err := pg.LinkExternalSubject(ctx, seededOrgID, user.ID, subject); err != nil {
		t.Fatalf("LinkExternalSubject: %v", err)
	}

	resolved, err := pg.GetUserByExternalSubject(ctx, subject)
	if err != nil {
		t.Fatalf("GetUserByExternalSubject: %v", err)
	}
	if resolved.ID != user.ID {
		t.Fatalf("resolved %q, want %q", resolved.ID, user.ID)
	}
	// The org the caller will act in comes from this row.
	if resolved.OrgID != seededOrgID {
		t.Fatalf("OrgID = %q", resolved.OrgID)
	}
	if resolved.Role != domain.RoleApprover {
		t.Fatalf("Role = %q, want the stored role", resolved.Role)
	}
}

// Rebinding must be impossible: a second identity claiming an already-linked
// account would inherit its role.
func TestLinkRefusesToRebindAnAlreadyLinkedAccount(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()

	email := fmt.Sprintf("rebind-%d@example.com", time.Now().UnixNano())
	user, err := pg.CreateUser(ctx, store.CreateUserInput{
		OrgID: seededOrgID, DisplayName: "Rebind Target", Email: &email, Role: domain.RoleAdmin,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	first := uniqueSubject("first")
	if err := pg.LinkExternalSubject(ctx, seededOrgID, user.ID, first); err != nil {
		t.Fatalf("first link: %v", err)
	}

	second := uniqueSubject("attacker")
	err = pg.LinkExternalSubject(ctx, seededOrgID, user.ID, second)
	var notFound domain.ErrNotFound
	if err == nil {
		t.Fatal("an already-linked account was rebound to a second identity")
	}
	if !asNotFound(err, &notFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}

	// The original binding must survive.
	resolved, err := pg.GetUserByExternalSubject(ctx, first)
	if err != nil || resolved.ID != user.ID {
		t.Fatalf("original link was disturbed: %v", err)
	}
}

// The unique index is the real defence: two actors must not be able to claim
// the same external identity, because which one a login resolved to would then
// depend on row order.
func TestExternalSubjectIsUniqueAcrossActors(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()

	subject := uniqueSubject("contested")
	stamp := time.Now().UnixNano()

	emailA := fmt.Sprintf("contest-a-%d@example.com", stamp)
	userA, err := pg.CreateUser(ctx, store.CreateUserInput{
		OrgID: seededOrgID, DisplayName: "A", Email: &emailA, Role: domain.RoleMember,
	})
	if err != nil {
		t.Fatalf("CreateUser A: %v", err)
	}
	emailB := fmt.Sprintf("contest-b-%d@example.com", stamp)
	userB, err := pg.CreateUser(ctx, store.CreateUserInput{
		OrgID: seededOrgID, DisplayName: "B", Email: &emailB, Role: domain.RoleAdmin,
	})
	if err != nil {
		t.Fatalf("CreateUser B: %v", err)
	}

	if err := pg.LinkExternalSubject(ctx, seededOrgID, userA.ID, subject); err != nil {
		t.Fatalf("link A: %v", err)
	}
	if err := pg.LinkExternalSubject(ctx, seededOrgID, userB.ID, subject); err == nil {
		t.Fatal("two actors were allowed to claim the same external identity")
	}
}

func TestGetUserByEmailIsCaseInsensitive(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()

	email := fmt.Sprintf("MixedCase-%d@Example.com", time.Now().UnixNano())
	user, err := pg.CreateUser(ctx, store.CreateUserInput{
		OrgID: seededOrgID, DisplayName: "Mixed", Email: &email, Role: domain.RoleMember,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// An identity provider will not preserve the casing an operator typed.
	found, err := pg.GetUserByEmail(ctx, lower(email))
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if found.ID != user.ID {
		t.Fatalf("found %q, want %q", found.ID, user.ID)
	}
}

// Linking must be org-scoped: naming the right user id under the wrong org
// must not bind anything.
func TestLinkIsOrgScoped(t *testing.T) {
	pg := newTestPostgres(t)
	ctx := context.Background()
	otherOrgID, _, _ := setupOtherOrg(t, pg)

	email := fmt.Sprintf("orgscope-%d@example.com", time.Now().UnixNano())
	user, err := pg.CreateUser(ctx, store.CreateUserInput{
		OrgID: seededOrgID, DisplayName: "Scoped", Email: &email, Role: domain.RoleMember,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	subject := uniqueSubject("scoped")
	if err := pg.LinkExternalSubject(ctx, otherOrgID, user.ID, subject); err == nil {
		t.Fatal("an actor was linked using another organization's id")
	}
	if _, err := pg.GetUserByExternalSubject(ctx, subject); err == nil {
		t.Fatal("the cross-org link took effect")
	}
}

func asNotFound(err error, target *domain.ErrNotFound) bool {
	for err != nil {
		if e, ok := err.(domain.ErrNotFound); ok {
			*target = e
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func lower(s string) string {
	out := []rune(s)
	for i, r := range out {
		if r >= 'A' && r <= 'Z' {
			out[i] = r + 32
		}
	}
	return string(out)
}

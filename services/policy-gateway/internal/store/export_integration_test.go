//go:build integration

package store

import (
	"context"
	"fmt"
)

// EnsureTestOrganization creates (or reuses) an organization by slug and
// returns its id. It exists only so integration tests can stand up a *second*
// tenant to prove cross-org isolation - the product itself has no
// create-organization path yet, and this must not become one. Being in a
// _test.go file behind the integration build tag, it is never compiled into a
// production binary.
func (p *Postgres) EnsureTestOrganization(ctx context.Context, slug, name string) (string, error) {
	var id string
	err := p.pool.QueryRow(ctx, `
		INSERT INTO organizations (slug, name)
		VALUES ($1, $2)
		ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name
		RETURNING id
	`, slug, name).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("ensure test organization: %w", err)
	}
	return id, nil
}

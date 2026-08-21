package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
)

func (p *Postgres) GetOrganization(ctx context.Context, id string) (domain.Organization, error) {
	var org domain.Organization
	err := p.pool.QueryRow(ctx, `
		SELECT id, slug, name, status, created_at, updated_at
		FROM organizations
		WHERE id = $1
	`, id).Scan(&org.ID, &org.Slug, &org.Name, &org.Status, &org.CreatedAt, &org.UpdatedAt)
	if err != nil {
		if isNoRows(err) {
			return domain.Organization{}, domain.ErrNotFound{Resource: "organization", ID: id}
		}
		return domain.Organization{}, fmt.Errorf("get organization: %w", err)
	}
	return org, nil
}

func (p *Postgres) ListUsers(ctx context.Context, in ListUsersInput) ([]domain.User, error) {
	limit, offset := normalizePage(in.Limit, in.Offset)
	rows, err := p.pool.Query(ctx, `
		SELECT id, org_id, display_name, email, role, status, external_subject, created_at, updated_at
		FROM actors
		WHERE org_id = $4
		  AND type != 'agent'
		  AND ($1 = '' OR status = $1)
		ORDER BY created_at ASC, id ASC
		LIMIT $2 OFFSET $3
	`, in.Status, limit, offset, in.OrgID)
	if err != nil {
		return nil, fmt.Errorf("query users: %w", err)
	}
	defer rows.Close()

	users := make([]domain.User, 0)
	for rows.Next() {
		user, err := scanUserRow(rows)
		if err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users: %w", err)
	}
	return users, nil
}

func (p *Postgres) GetUser(ctx context.Context, orgID, id string) (domain.User, error) {
	row := p.pool.QueryRow(ctx, `
		SELECT id, org_id, display_name, email, role, status, external_subject, created_at, updated_at
		FROM actors
		WHERE id = $1 AND org_id = $2 AND type != 'agent'
	`, id, orgID)

	user, err := scanUserRow(row)
	if err != nil {
		if isNoRows(err) {
			return domain.User{}, domain.ErrNotFound{Resource: "user", ID: id}
		}
		return domain.User{}, fmt.Errorf("get user: %w", err)
	}
	return user, nil
}

func (p *Postgres) CreateUser(ctx context.Context, in CreateUserInput) (domain.User, error) {
	row := p.pool.QueryRow(ctx, `
		INSERT INTO actors (type, org_id, display_name, email, role)
		VALUES ('user', $1, $2, NULLIF($3, ''), $4)
		RETURNING id, org_id, display_name, email, role, status, external_subject, created_at, updated_at
	`, in.OrgID, in.DisplayName, derefString(in.Email), in.Role)

	user, err := scanUserRow(row)
	if err != nil {
		return domain.User{}, fmt.Errorf("create user: %w", err)
	}
	return user, nil
}

func (p *Postgres) UpdateUser(ctx context.Context, orgID, id string, in UpdateUserInput) (domain.User, error) {
	row := p.pool.QueryRow(ctx, `
		UPDATE actors
		SET display_name = COALESCE($2, display_name),
		    email = CASE WHEN $3::boolean THEN NULLIF($4, '') ELSE email END,
		    role = COALESCE($5, role),
		    status = COALESCE($6, status),
		    updated_at = NOW()
		WHERE id = $1 AND org_id = $7 AND type != 'agent'
		RETURNING id, org_id, display_name, email, role, status, external_subject, created_at, updated_at
	`, id, in.DisplayName, in.Email != nil, derefString(in.Email), in.Role, in.Status, orgID)

	user, err := scanUserRow(row)
	if err != nil {
		if isNoRows(err) {
			return domain.User{}, domain.ErrNotFound{Resource: "user", ID: id}
		}
		return domain.User{}, fmt.Errorf("update user: %w", err)
	}
	return user, nil
}

func scanUserRow(row pgxRow) (domain.User, error) {
	var user domain.User
	if err := row.Scan(
		&user.ID,
		&user.OrgID,
		&user.DisplayName,
		&user.Email,
		&user.Role,
		&user.Status,
		&user.ExternalSubject,
		&user.CreatedAt,
		&user.UpdatedAt,
	); err != nil {
		return domain.User{}, err
	}
	return user, nil
}

func (p *Postgres) ListAgents(ctx context.Context, in ListAgentsInput) ([]domain.Agent, error) {
	limit, offset := normalizePage(in.Limit, in.Offset)
	rows, err := p.pool.Query(ctx, `
		SELECT ag.id, ag.org_id, ag.actor_id, COALESCE(owner.display_name, ''), ag.name, ag.container_id,
		       ag.status, ag.last_seen_at, ag.revoked_at, ag.metadata_json, ag.created_at, ag.updated_at
		FROM agents ag
		LEFT JOIN actors owner ON owner.id = ag.actor_id
		WHERE ag.org_id = $5
		  AND ($1 = '' OR ag.actor_id::text = $1)
		  AND ($2 = '' OR ag.status = $2)
		ORDER BY ag.created_at ASC, ag.id ASC
		LIMIT $3 OFFSET $4
	`, in.UserID, in.Status, limit, offset, in.OrgID)
	if err != nil {
		return nil, fmt.Errorf("query agents: %w", err)
	}
	defer rows.Close()

	agents := make([]domain.Agent, 0)
	for rows.Next() {
		agent, err := scanAgentRow(rows)
		if err != nil {
			return nil, fmt.Errorf("scan agent: %w", err)
		}
		agents = append(agents, agent)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate agents: %w", err)
	}
	return agents, nil
}

func (p *Postgres) GetAgent(ctx context.Context, orgID, id string) (domain.Agent, error) {
	row := p.pool.QueryRow(ctx, `
		SELECT ag.id, ag.org_id, ag.actor_id, COALESCE(owner.display_name, ''), ag.name, ag.container_id,
		       ag.status, ag.last_seen_at, ag.revoked_at, ag.metadata_json, ag.created_at, ag.updated_at
		FROM agents ag
		LEFT JOIN actors owner ON owner.id = ag.actor_id
		WHERE ag.id = $1 AND ag.org_id = $2
	`, id, orgID)

	agent, err := scanAgentRow(row)
	if err != nil {
		if isNoRows(err) {
			return domain.Agent{}, domain.ErrNotFound{Resource: "agent", ID: id}
		}
		return domain.Agent{}, fmt.Errorf("get agent: %w", err)
	}
	return agent, nil
}

// ResolveAgentForAuth is the one deliberately un-org-scoped agent lookup. It
// exists solely for the credential-to-identity hop inside authentication,
// where the agent's own org is the *result* being resolved and so cannot also
// be a filter on the query. Never call it from a request handler: any
// caller-facing path must use the org-scoped GetAgent instead.
func (p *Postgres) ResolveAgentForAuth(ctx context.Context, id string) (domain.Agent, error) {
	row := p.pool.QueryRow(ctx, `
		SELECT ag.id, ag.org_id, ag.actor_id, COALESCE(owner.display_name, ''), ag.name, ag.container_id,
		       ag.status, ag.last_seen_at, ag.revoked_at, ag.metadata_json, ag.created_at, ag.updated_at
		FROM agents ag
		LEFT JOIN actors owner ON owner.id = ag.actor_id
		WHERE ag.id = $1
	`, id)

	agent, err := scanAgentRow(row)
	if err != nil {
		if isNoRows(err) {
			return domain.Agent{}, domain.ErrNotFound{Resource: "agent", ID: id}
		}
		return domain.Agent{}, fmt.Errorf("resolve agent for auth: %w", err)
	}
	return agent, nil
}

func (p *Postgres) UpdateAgent(ctx context.Context, orgID, id string, in UpdateAgentInput) (domain.Agent, error) {
	// Always bind valid JSON for $6, even when unused (hasMetadata false):
	// Postgres validates a ::jsonb cast at parameter-bind time regardless of
	// which CASE branch ends up selected at row-evaluation time, so an empty
	// string here would fail the cast even though that branch is never taken.
	metadataJSON := []byte("null")
	hasMetadata := in.Metadata != nil
	if hasMetadata {
		marshaled, err := json.Marshal(in.Metadata)
		if err != nil {
			return domain.Agent{}, fmt.Errorf("marshal agent metadata: %w", err)
		}
		metadataJSON = marshaled
	}

	tag, err := p.pool.Exec(ctx, `
		UPDATE agents
		SET name = COALESCE($2, name),
		    container_id = CASE WHEN $3::boolean THEN $4 ELSE container_id END,
		    metadata_json = CASE WHEN $5::boolean THEN $6::jsonb ELSE metadata_json END,
		    updated_at = NOW()
		WHERE id = $1 AND org_id = $7
	`, id, in.Name, in.ContainerID != nil, in.ContainerID, hasMetadata, string(metadataJSON), orgID)
	if err != nil {
		return domain.Agent{}, fmt.Errorf("update agent: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.Agent{}, domain.ErrNotFound{Resource: "agent", ID: id}
	}

	return p.GetAgent(ctx, orgID, id)
}

func scanAgentRow(row pgxRow) (domain.Agent, error) {
	var agent domain.Agent
	var metadataRaw []byte
	if err := row.Scan(
		&agent.ID,
		&agent.OrgID,
		&agent.OwnerUserID,
		&agent.OwnerDisplayName,
		&agent.Name,
		&agent.ContainerID,
		&agent.Status,
		&agent.LastSeenAt,
		&agent.RevokedAt,
		&metadataRaw,
		&agent.CreatedAt,
		&agent.UpdatedAt,
	); err != nil {
		return domain.Agent{}, err
	}
	agent.MetadataJSON = metadataRaw
	if len(metadataRaw) == 0 {
		agent.Metadata = map[string]any{}
	} else if err := json.Unmarshal(metadataRaw, &agent.Metadata); err != nil {
		return domain.Agent{}, fmt.Errorf("decode agent metadata: %w", err)
	}
	return agent, nil
}

func (p *Postgres) RegisterAgent(ctx context.Context, in RegisterAgentInput, audit AuditInput) (domain.Agent, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return domain.Agent{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	metadata := in.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return domain.Agent{}, fmt.Errorf("marshal agent metadata: %w", err)
	}

	// The owner must live in the same org the agent is being created in;
	// otherwise a known user UUID from another tenant could seed an agent here.
	var ownerOrgID string
	if err := tx.QueryRow(ctx, `
		SELECT org_id FROM actors WHERE id = $1 AND type != 'agent'
	`, in.OwnerUserID).Scan(&ownerOrgID); err != nil {
		if isNoRows(err) {
			return domain.Agent{}, domain.ErrNotFound{Resource: "user", ID: in.OwnerUserID}
		}
		return domain.Agent{}, fmt.Errorf("look up agent owner: %w", err)
	}
	if ownerOrgID != in.OrgID {
		return domain.Agent{}, domain.ErrNotFound{Resource: "user", ID: in.OwnerUserID}
	}

	var agentID string
	err = tx.QueryRow(ctx, `
		INSERT INTO agents (org_id, actor_id, name, container_id, metadata_json)
		VALUES ($1, $2, $3, $4, $5::jsonb)
		RETURNING id
	`, in.OrgID, in.OwnerUserID, in.Name, in.ContainerID, string(metadataJSON)).Scan(&agentID)
	if err != nil {
		return domain.Agent{}, fmt.Errorf("insert agent: %w", err)
	}

	audit.Metadata = enrichAgentAuditMetadata(audit.Metadata, agentID, in.Name)
	if err := p.insertAuditEvent(ctx, tx, in.OrgID, audit.EgressRequestID, audit.EventType, audit.ActorID, audit.Metadata); err != nil {
		return domain.Agent{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.Agent{}, fmt.Errorf("commit register agent: %w", err)
	}

	return p.GetAgent(ctx, in.OrgID, agentID)
}

func (p *Postgres) RevokeAgent(ctx context.Context, orgID, agentID string, audit AuditInput) (domain.Agent, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return domain.Agent{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx, `
		UPDATE agents
		SET status = 'revoked', revoked_at = NOW(), updated_at = NOW()
		WHERE id = $1 AND org_id = $2 AND status != 'revoked'
	`, agentID, orgID)
	if err != nil {
		return domain.Agent{}, fmt.Errorf("revoke agent: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Either already revoked, or not ours. GetAgent is org-scoped, so the
		// second case surfaces as ErrNotFound rather than a silent no-op.
		if _, lookupErr := p.GetAgent(ctx, orgID, agentID); lookupErr != nil {
			return domain.Agent{}, lookupErr
		}
	}

	if _, err := tx.Exec(ctx, `
		UPDATE agent_credentials
		SET status = 'revoked', revoked_at = NOW()
		WHERE agent_id = $1 AND status = 'active'
		  AND agent_id IN (SELECT id FROM agents WHERE org_id = $2)
	`, agentID, orgID); err != nil {
		return domain.Agent{}, fmt.Errorf("revoke agent credentials: %w", err)
	}

	audit.Metadata = enrichAgentAuditMetadata(audit.Metadata, agentID, "")
	if err := p.insertAuditEvent(ctx, tx, orgID, audit.EgressRequestID, audit.EventType, audit.ActorID, audit.Metadata); err != nil {
		return domain.Agent{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.Agent{}, fmt.Errorf("commit revoke agent: %w", err)
	}

	return p.GetAgent(ctx, orgID, agentID)
}

func enrichAgentAuditMetadata(metadata map[string]any, agentID, name string) map[string]any {
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["agent_id"] = agentID
	if name != "" {
		metadata["agent_name"] = name
	}
	return metadata
}

// GetUserByExternalSubject resolves a verified external identity (Phase 5.13)
// to its Clearance actor.
//
// Deliberately not org-scoped: this is the authentication hop that *produces*
// the caller's organization, so there is no org to filter by yet. Everything
// the caller does afterwards is scoped to the org this returns.
func (p *Postgres) GetUserByExternalSubject(ctx context.Context, externalSubject string) (domain.User, error) {
	row := p.pool.QueryRow(ctx, `
		SELECT id, org_id, display_name, email, role, status, external_subject, created_at, updated_at
		FROM actors
		WHERE external_subject = $1 AND type != 'agent'
	`, externalSubject)

	user, err := scanUserRow(row)
	if err != nil {
		if isNoRows(err) {
			return domain.User{}, domain.ErrNotFound{Resource: "user", ID: "external_subject"}
		}
		return domain.User{}, fmt.Errorf("get user by external subject: %w", err)
	}
	return user, nil
}

// GetUserByEmail resolves an actor by email for just-in-time linking of a
// first OIDC login to a pre-created account.
//
// Email is not unique across organizations, and an ambiguous match must not be
// resolved arbitrarily - picking one would let an account in org A be claimed
// by an identity intended for org B. Ambiguity is reported as an error so the
// caller refuses rather than guesses.
func (p *Postgres) GetUserByEmail(ctx context.Context, email string) (domain.User, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, org_id, display_name, email, role, status, external_subject, created_at, updated_at
		FROM actors
		WHERE lower(email) = lower($1) AND type != 'agent'
		LIMIT 2
	`, email)
	if err != nil {
		return domain.User{}, fmt.Errorf("get user by email: %w", err)
	}
	defer rows.Close()

	var found []domain.User
	for rows.Next() {
		user, scanErr := scanUserRow(rows)
		if scanErr != nil {
			return domain.User{}, fmt.Errorf("scan user by email: %w", scanErr)
		}
		found = append(found, user)
	}
	if err := rows.Err(); err != nil {
		return domain.User{}, fmt.Errorf("iterate users by email: %w", err)
	}

	switch len(found) {
	case 0:
		return domain.User{}, domain.ErrNotFound{Resource: "user", ID: "email"}
	case 1:
		return found[0], nil
	default:
		return domain.User{}, domain.ErrAmbiguousEmail{Email: email}
	}
}

// LinkExternalSubject binds a verified external identity to an actor, but only
// if that actor has no external identity yet.
//
// The NULL check is the security-relevant part: without it, a second identity
// provider (or a re-registered subject at the same provider) could rebind an
// existing account and inherit its role. Rebinding is an operator action, not
// something a login should be able to do.
func (p *Postgres) LinkExternalSubject(ctx context.Context, orgID, userID, externalSubject string) error {
	tag, err := p.pool.Exec(ctx, `
		UPDATE actors
		SET external_subject = $3, updated_at = NOW()
		WHERE id = $1
		  AND org_id = $2
		  AND type != 'agent'
		  AND (external_subject IS NULL OR external_subject = '')
	`, userID, orgID, externalSubject)
	if err != nil {
		return fmt.Errorf("link external subject: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound{Resource: "user", ID: userID}
	}
	return nil
}

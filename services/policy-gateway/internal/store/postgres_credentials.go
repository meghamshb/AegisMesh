package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
)

func (p *Postgres) CreateAgentCredential(ctx context.Context, in CreateAgentCredentialInput, audit AuditInput) (domain.AgentCredential, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return domain.AgentCredential{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if err := assertAgentInOrgTx(ctx, tx, in.OrgID, in.AgentID); err != nil {
		return domain.AgentCredential{}, err
	}

	cred, err := p.insertAgentCredentialTx(ctx, tx, in)
	if err != nil {
		return domain.AgentCredential{}, err
	}

	audit.Metadata = enrichCredentialAuditMetadata(audit.Metadata, cred)
	if err := p.insertAuditEvent(ctx, tx, in.OrgID, audit.EgressRequestID, audit.EventType, audit.ActorID, audit.Metadata); err != nil {
		return domain.AgentCredential{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.AgentCredential{}, fmt.Errorf("commit create agent credential: %w", err)
	}
	return cred, nil
}

func (p *Postgres) RotateAgentCredential(ctx context.Context, orgID, agentID string, in CreateAgentCredentialInput, audit AuditInput) (domain.AgentCredential, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return domain.AgentCredential{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Rotation mints a working agent token, so the org check has to happen
	// before anything else: without it, knowing only a victim tenant's agent
	// UUID would be enough to be handed a live credential for that agent.
	if err := assertAgentInOrgTx(ctx, tx, orgID, agentID); err != nil {
		return domain.AgentCredential{}, err
	}

	if _, err := tx.Exec(ctx, `
		UPDATE agent_credentials
		SET status = 'revoked', revoked_at = NOW()
		WHERE agent_id = $1 AND status = 'active'
	`, agentID); err != nil {
		return domain.AgentCredential{}, fmt.Errorf("revoke prior agent credentials: %w", err)
	}

	in.OrgID = orgID
	in.AgentID = agentID
	cred, err := p.insertAgentCredentialTx(ctx, tx, in)
	if err != nil {
		return domain.AgentCredential{}, err
	}

	audit.Metadata = enrichCredentialAuditMetadata(audit.Metadata, cred)
	if err := p.insertAuditEvent(ctx, tx, orgID, audit.EgressRequestID, audit.EventType, audit.ActorID, audit.Metadata); err != nil {
		return domain.AgentCredential{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.AgentCredential{}, fmt.Errorf("commit rotate agent credential: %w", err)
	}
	return cred, nil
}

// assertAgentInOrgTx fails with ErrNotFound when the agent is missing *or*
// belongs to another organization - the caller must not be able to tell those
// two cases apart.
func assertAgentInOrgTx(ctx context.Context, tx pgx.Tx, orgID, agentID string) error {
	var found string
	err := tx.QueryRow(ctx, `SELECT id FROM agents WHERE id = $1 AND org_id = $2`, agentID, orgID).Scan(&found)
	if err != nil {
		if isNoRows(err) {
			return domain.ErrNotFound{Resource: "agent", ID: agentID}
		}
		return fmt.Errorf("verify agent organization: %w", err)
	}
	return nil
}

func (p *Postgres) insertAgentCredentialTx(ctx context.Context, tx pgx.Tx, in CreateAgentCredentialInput) (domain.AgentCredential, error) {
	var cred domain.AgentCredential
	err := tx.QueryRow(ctx, `
		INSERT INTO agent_credentials (agent_id, token_prefix, token_hash, created_by)
		VALUES ($1, $2, $3, NULLIF($4, '')::uuid)
		RETURNING id, agent_id, token_prefix, token_hash, status, COALESCE(created_by::text, ''), created_at, last_used_at, revoked_at
	`, in.AgentID, in.TokenPrefix, in.TokenHash, in.CreatedBy).Scan(
		&cred.ID,
		&cred.AgentID,
		&cred.TokenPrefix,
		&cred.TokenHash,
		&cred.Status,
		&cred.CreatedBy,
		&cred.CreatedAt,
		&cred.LastUsedAt,
		&cred.RevokedAt,
	)
	if err != nil {
		return domain.AgentCredential{}, fmt.Errorf("insert agent credential: %w", err)
	}
	return cred, nil
}

// GetAgentCredentialByHash is intentionally not org-scoped: it runs before any
// caller org is known, and the token hash is itself the authenticator. The
// org is an *output* of this lookup, not an input to it.
func (p *Postgres) GetAgentCredentialByHash(ctx context.Context, tokenHash string) (domain.AgentCredential, error) {
	row := p.pool.QueryRow(ctx, `
		SELECT id, agent_id, token_prefix, token_hash, status, COALESCE(created_by::text, ''), created_at, last_used_at, revoked_at
		FROM agent_credentials
		WHERE token_hash = $1
	`, tokenHash)

	var cred domain.AgentCredential
	if err := row.Scan(
		&cred.ID,
		&cred.AgentID,
		&cred.TokenPrefix,
		&cred.TokenHash,
		&cred.Status,
		&cred.CreatedBy,
		&cred.CreatedAt,
		&cred.LastUsedAt,
		&cred.RevokedAt,
	); err != nil {
		if isNoRows(err) {
			return domain.AgentCredential{}, domain.ErrNotFound{Resource: "agent_credential", ID: "token"}
		}
		return domain.AgentCredential{}, fmt.Errorf("get agent credential: %w", err)
	}
	return cred, nil
}

func (p *Postgres) TouchAgentCredentialLastUsed(ctx context.Context, credentialID string) error {
	_, err := p.pool.Exec(ctx, `
		UPDATE agent_credentials SET last_used_at = NOW() WHERE id = $1
	`, credentialID)
	if err != nil {
		return fmt.Errorf("touch agent credential last_used_at: %w", err)
	}
	return nil
}

func (p *Postgres) TouchAgentLastSeen(ctx context.Context, agentID string) error {
	_, err := p.pool.Exec(ctx, `
		UPDATE agents SET last_seen_at = NOW() WHERE id = $1
	`, agentID)
	if err != nil {
		return fmt.Errorf("touch agent last_seen_at: %w", err)
	}
	return nil
}

func enrichCredentialAuditMetadata(metadata map[string]any, cred domain.AgentCredential) map[string]any {
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["agent_id"] = cred.AgentID
	metadata["credential_id"] = cred.ID
	metadata["token_prefix"] = cred.TokenPrefix
	return metadata
}

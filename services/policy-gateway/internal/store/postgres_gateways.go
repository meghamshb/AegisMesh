package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
)

func (p *Postgres) RegisterGateway(ctx context.Context, in RegisterGatewayInput) (domain.Gateway, error) {
	metadata := in.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return domain.Gateway{}, fmt.Errorf("marshal gateway metadata: %w", err)
	}

	row := p.pool.QueryRow(ctx, `
		INSERT INTO gateways (org_id, name, credential_hash, credential_prefix, metadata_json)
		VALUES ($1, $2, $3, $4, $5::jsonb)
		RETURNING id, org_id, name, status, credential_prefix, credential_hash, version,
		          policy_version, active_agents, metadata_json, last_seen_at, created_at, revoked_at
	`, in.OrgID, in.Name, in.CredentialHash, in.CredentialPrefix, string(metadataJSON))

	gw, err := scanGatewayRow(row)
	if err != nil {
		return domain.Gateway{}, fmt.Errorf("register gateway: %w", err)
	}
	return gw, nil
}

func (p *Postgres) ListGateways(ctx context.Context, orgID string) ([]domain.Gateway, error) {
	// No empty-orgID wildcard: an unset org must return nothing, never every
	// tenant's fleet.
	rows, err := p.pool.Query(ctx, `
		SELECT id, org_id, name, status, credential_prefix, credential_hash, version,
		       policy_version, active_agents, metadata_json, last_seen_at, created_at, revoked_at
		FROM gateways
		WHERE org_id = $1
		ORDER BY created_at ASC, id ASC
	`, orgID)
	if err != nil {
		return nil, fmt.Errorf("query gateways: %w", err)
	}
	defer rows.Close()

	gateways := make([]domain.Gateway, 0)
	for rows.Next() {
		gw, err := scanGatewayRow(rows)
		if err != nil {
			return nil, fmt.Errorf("scan gateway: %w", err)
		}
		gateways = append(gateways, gw)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate gateways: %w", err)
	}
	return gateways, nil
}

func (p *Postgres) GetGateway(ctx context.Context, orgID, id string) (domain.Gateway, error) {
	row := p.pool.QueryRow(ctx, `
		SELECT id, org_id, name, status, credential_prefix, credential_hash, version,
		       policy_version, active_agents, metadata_json, last_seen_at, created_at, revoked_at
		FROM gateways
		WHERE id = $1 AND org_id = $2
	`, id, orgID)

	gw, err := scanGatewayRow(row)
	if err != nil {
		if isNoRows(err) {
			return domain.Gateway{}, domain.ErrNotFound{Resource: "gateway", ID: id}
		}
		return domain.Gateway{}, fmt.Errorf("get gateway: %w", err)
	}
	return gw, nil
}

// GetGatewayByCredentialHash, like the agent-credential equivalent, resolves an
// org rather than being filtered by one - the hash is the authenticator.
func (p *Postgres) GetGatewayByCredentialHash(ctx context.Context, credentialHash string) (domain.Gateway, error) {
	row := p.pool.QueryRow(ctx, `
		SELECT id, org_id, name, status, credential_prefix, credential_hash, version,
		       policy_version, active_agents, metadata_json, last_seen_at, created_at, revoked_at
		FROM gateways
		WHERE credential_hash = $1
	`, credentialHash)

	gw, err := scanGatewayRow(row)
	if err != nil {
		if isNoRows(err) {
			return domain.Gateway{}, domain.ErrNotFound{Resource: "gateway", ID: "credential"}
		}
		return domain.Gateway{}, fmt.Errorf("get gateway by credential: %w", err)
	}
	return gw, nil
}

func (p *Postgres) UpdateGatewayHeartbeat(ctx context.Context, orgID, id string, in GatewayHeartbeatInput) (domain.Gateway, error) {
	metadataJSON := []byte("null")
	hasMetadata := in.Metadata != nil
	if hasMetadata {
		marshaled, err := json.Marshal(in.Metadata)
		if err != nil {
			return domain.Gateway{}, fmt.Errorf("marshal gateway metadata: %w", err)
		}
		metadataJSON = marshaled
	}

	tag, err := p.pool.Exec(ctx, `
		UPDATE gateways
		SET last_seen_at = NOW(),
		    version = CASE WHEN $2::boolean THEN $3 ELSE version END,
		    policy_version = $7,
		    active_agents = $8,
		    metadata_json = CASE WHEN $4::boolean THEN $5::jsonb ELSE metadata_json END
		WHERE id = $1 AND org_id = $6
	`, id, in.Version != "", in.Version, hasMetadata, string(metadataJSON), orgID, in.PolicyVersion, in.ActiveAgents)
	if err != nil {
		return domain.Gateway{}, fmt.Errorf("update gateway heartbeat: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.Gateway{}, domain.ErrNotFound{Resource: "gateway", ID: id}
	}

	return p.GetGateway(ctx, orgID, id)
}

func scanGatewayRow(row pgxRow) (domain.Gateway, error) {
	var gw domain.Gateway
	var version *string
	var metadataRaw []byte
	if err := row.Scan(
		&gw.ID,
		&gw.OrgID,
		&gw.Name,
		&gw.Status,
		&gw.CredentialPrefix,
		&gw.CredentialHash,
		&version,
		&gw.PolicyVersion,
		&gw.ActiveAgents,
		&metadataRaw,
		&gw.LastSeenAt,
		&gw.CreatedAt,
		&gw.RevokedAt,
	); err != nil {
		return domain.Gateway{}, err
	}
	if version != nil {
		gw.Version = *version
	}
	gw.MetadataJSON = metadataRaw
	if len(metadataRaw) == 0 {
		gw.Metadata = map[string]any{}
	} else if err := json.Unmarshal(metadataRaw, &gw.Metadata); err != nil {
		return domain.Gateway{}, fmt.Errorf("decode gateway metadata: %w", err)
	}
	return gw, nil
}

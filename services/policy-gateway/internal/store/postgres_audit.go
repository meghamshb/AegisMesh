package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
)

func (p *Postgres) ListAuditEvents(ctx context.Context, in ListAuditEventsInput) ([]domain.AuditEvent, error) {
	limit, offset := normalizePage(in.Limit, in.Offset)
	rows, err := p.pool.Query(ctx, `
		SELECT id, org_id, egress_request_id, event_type, actor_id, metadata_json, created_at
		FROM audit_events
		WHERE org_id = $7
		  AND ($1 = '' OR event_type = $1)
		  AND ($2 = '' OR actor_id::text = $2)
		  AND ($3::timestamptz IS NULL OR created_at >= $3)
		  AND ($4::timestamptz IS NULL OR created_at <= $4)
		ORDER BY created_at DESC, id DESC
		LIMIT $5 OFFSET $6
	`, in.EventType, in.ActorID, in.From, in.To, limit, offset, in.OrgID)
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()

	return scanAuditEvents(rows)
}

func (p *Postgres) InsertAuditEvent(ctx context.Context, orgID, egressRequestID, eventType, actorID string, metadata map[string]any) error {
	return p.insertAuditEvent(ctx, p.pool, orgID, egressRequestID, eventType, actorID, metadata)
}

func (p *Postgres) insertAuditEvent(ctx context.Context, exec queryExecutor, orgID, egressRequestID, eventType, actorID string, metadata map[string]any) error {
	payload, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("marshal audit metadata: %w", err)
	}

	_, err = exec.Exec(ctx, `
		INSERT INTO audit_events (org_id, egress_request_id, event_type, actor_id, metadata_json)
		VALUES ($1::uuid, $2::uuid, $3, NULLIF($4, '')::uuid, $5::jsonb)
	`, orgID, nullIfEmpty(egressRequestID), eventType, actorID, string(payload))
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

func scanAuditEvents(rows pgxRows) ([]domain.AuditEvent, error) {
	events := make([]domain.AuditEvent, 0)
	for rows.Next() {
		var (
			event       domain.AuditEvent
			rawMetadata []byte
		)
		if err := rows.Scan(
			&event.ID,
			&event.OrgID,
			&event.EgressRequestID,
			&event.EventType,
			&event.ActorID,
			&rawMetadata,
			&event.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		if len(rawMetadata) == 0 {
			event.Metadata = map[string]any{}
		} else if err := json.Unmarshal(rawMetadata, &event.Metadata); err != nil {
			return nil, fmt.Errorf("decode audit event metadata: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit events: %w", err)
	}
	return events, nil
}

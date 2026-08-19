package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/domain"
)

type Postgres struct {
	pool *pgxpool.Pool
}

func NewPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("create postgres pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	return &Postgres{pool: pool}, nil
}

func (p *Postgres) Close() {
	p.pool.Close()
}

func (p *Postgres) Ping(ctx context.Context) error {
	return p.pool.Ping(ctx)
}

func (p *Postgres) ListRequests(ctx context.Context, in ListRequestsInput) ([]domain.EgressRequest, error) {
	baseQuery := `
		SELECT id, agent_id, user_id, org_id, method, host, port, path, scheme,
		       status, rule_id, requested_at, decided_at, decided_by, error_message, consumed_at
		FROM egress_requests
		WHERE ($1 = '' OR status = $1)
		  AND ($2 = '' OR host ILIKE '%' || $2 || '%')
		  AND ($3 = '' OR user_id::text = $3)
		  AND ($4 = '' OR agent_id::text = $4)
		ORDER BY requested_at DESC
		LIMIT $5
	`
	status := ""
	if in.Status != nil {
		status = string(*in.Status)
	}
	limit := in.Limit
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.pool.Query(ctx, baseQuery, status, in.Host, in.UserID, in.AgentID, limit)
	if err != nil {
		return nil, fmt.Errorf("query egress requests: %w", err)
	}
	defer rows.Close()

	return scanEgressRequests(rows)
}

func (p *Postgres) ListRules(ctx context.Context) ([]domain.PolicyRule, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, org_id, scope, scope_ref_id, effect, host, port, method,
		       path_prefix, created_at, created_by, expires_at
		FROM policy_rules
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("query policy rules: %w", err)
	}
	defer rows.Close()

	return scanPolicyRules(rows)
}

func (p *Postgres) ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, egress_request_id, event_type, actor_id, metadata_json, created_at
		FROM audit_events
		ORDER BY created_at DESC
		LIMIT 100
	`)
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()

	return scanAuditEvents(rows)
}

func (p *Postgres) MatchRules(ctx context.Context, in MatchRulesInput) ([]domain.PolicyRule, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, org_id, scope, scope_ref_id, effect, host, port, method,
		       path_prefix, created_at, created_by, expires_at
		FROM policy_rules
		WHERE org_id = $1
		  AND host = $2
		  AND port = $3
		  AND (method = '*' OR method = $4)
		  AND $5 LIKE path_prefix || '%'
		  AND (expires_at IS NULL OR expires_at > NOW())
	`, in.OrgID, in.Host, in.Port, in.Method, in.Path)
	if err != nil {
		return nil, fmt.Errorf("match policy rules: %w", err)
	}
	defer rows.Close()

	return scanPolicyRules(rows)
}

func (p *Postgres) CreateEgressRequest(ctx context.Context, in CreateEgressRequestInput) (domain.EgressRequest, error) {
	status, err := domain.ParseRequestStatus(string(in.Status))
	if err != nil {
		return domain.EgressRequest{}, err
	}

	var req domain.EgressRequest
	err = p.pool.QueryRow(ctx, `
		INSERT INTO egress_requests (
			agent_id, user_id, org_id, method, host, port, path, scheme, status, rule_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, agent_id, user_id, org_id, method, host, port, path, scheme,
		          status, rule_id, requested_at, decided_at, decided_by, error_message, consumed_at
	`, in.AgentID, in.UserID, in.OrgID, in.Method, in.Host, in.Port, in.Path, in.Scheme, string(status), in.RuleID).Scan(
		&req.ID,
		&req.AgentID,
		&req.UserID,
		&req.OrgID,
		&req.Method,
		&req.Host,
		&req.Port,
		&req.Path,
		&req.Scheme,
		&req.Status,
		&req.RuleID,
		&req.RequestedAt,
		&req.DecidedAt,
		&req.DecidedBy,
		&req.ErrorMessage,
		&req.ConsumedAt,
	)
	if err != nil {
		return domain.EgressRequest{}, fmt.Errorf("insert egress request: %w", err)
	}

	return req, nil
}

func (p *Postgres) InsertAuditEvent(ctx context.Context, egressRequestID, eventType, actorID string, metadata map[string]any) error {
	payload, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("marshal audit metadata: %w", err)
	}

	_, err = p.pool.Exec(ctx, `
		INSERT INTO audit_events (egress_request_id, event_type, actor_id, metadata_json)
		VALUES ($1::uuid, $2, NULLIF($3, '')::uuid, $4::jsonb)
	`, nullIfEmpty(egressRequestID), eventType, actorID, string(payload))
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

func (p *Postgres) GetEgressRequest(ctx context.Context, id string) (domain.EgressRequest, error) {
	row := p.pool.QueryRow(ctx, `
		SELECT id, agent_id, user_id, org_id, method, host, port, path, scheme,
		       status, rule_id, requested_at, decided_at, decided_by, error_message, consumed_at
		FROM egress_requests
		WHERE id = $1
	`, id)

	req, err := scanEgressRequestRow(row)
	if err != nil {
		if isNoRows(err) {
			return domain.EgressRequest{}, domain.ErrNotFound{Resource: "egress_request", ID: id}
		}
		return domain.EgressRequest{}, fmt.Errorf("get egress request: %w", err)
	}
	return req, nil
}

func (p *Postgres) ApproveRequestOnce(ctx context.Context, id, decidedBy string) (domain.EgressRequest, error) {
	row := p.pool.QueryRow(ctx, `
		UPDATE egress_requests
		SET status = 'approved', decided_at = NOW(), decided_by = $2
		WHERE id = $1 AND status = 'pending'
		RETURNING id, agent_id, user_id, org_id, method, host, port, path, scheme,
		          status, rule_id, requested_at, decided_at, decided_by, error_message, consumed_at
	`, id, decidedBy)

	req, err := scanEgressRequestRow(row)
	if err != nil {
		if isNoRows(err) {
			existing, lookupErr := p.GetEgressRequest(ctx, id)
			if lookupErr != nil {
				return domain.EgressRequest{}, domain.ErrNotFound{Resource: "egress_request", ID: id}
			}
			return domain.EgressRequest{}, domain.ErrRequestNotPending{ID: id, Status: existing.Status}
		}
		return domain.EgressRequest{}, fmt.Errorf("approve egress request: %w", err)
	}
	return req, nil
}

func (p *Postgres) DenyRequest(ctx context.Context, id, decidedBy, feedback string) (domain.EgressRequest, error) {
	row := p.pool.QueryRow(ctx, `
		UPDATE egress_requests
		SET status = 'denied',
		    decided_at = NOW(),
		    decided_by = $2,
		    error_message = NULLIF($3, '')
		WHERE id = $1 AND status = 'pending'
		RETURNING id, agent_id, user_id, org_id, method, host, port, path, scheme,
		          status, rule_id, requested_at, decided_at, decided_by, error_message, consumed_at
	`, id, decidedBy, feedback)

	req, err := scanEgressRequestRow(row)
	if err != nil {
		if isNoRows(err) {
			existing, lookupErr := p.GetEgressRequest(ctx, id)
			if lookupErr != nil {
				return domain.EgressRequest{}, domain.ErrNotFound{Resource: "egress_request", ID: id}
			}
			return domain.EgressRequest{}, domain.ErrRequestNotPending{ID: id, Status: existing.Status}
		}
		return domain.EgressRequest{}, fmt.Errorf("deny egress request: %w", err)
	}
	return req, nil
}

func (p *Postgres) FindConsumableApproval(ctx context.Context, in ApprovalMatchInput) (*domain.EgressRequest, error) {
	row := p.pool.QueryRow(ctx, `
		SELECT id, agent_id, user_id, org_id, method, host, port, path, scheme,
		       status, rule_id, requested_at, decided_at, decided_by, error_message, consumed_at
		FROM egress_requests
		WHERE agent_id = $1
		  AND host = $2
		  AND port = $3
		  AND method = $4
		  AND path = $5
		  AND status = 'approved'
		  AND consumed_at IS NULL
		ORDER BY decided_at DESC
		LIMIT 1
	`, in.AgentID, in.Host, in.Port, in.Method, in.Path)

	req, err := scanEgressRequestRow(row)
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("find consumable approval: %w", err)
	}
	return &req, nil
}

func (p *Postgres) HasDeniedPattern(ctx context.Context, in ApprovalMatchInput) (bool, error) {
	var exists bool
	err := p.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM egress_requests
			WHERE agent_id = $1
			  AND host = $2
			  AND port = $3
			  AND method = $4
			  AND path = $5
			  AND status = 'denied'
		)
	`, in.AgentID, in.Host, in.Port, in.Method, in.Path).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check denied pattern: %w", err)
	}
	return exists, nil
}

func (p *Postgres) MarkApprovalConsumed(ctx context.Context, id string) error {
	tag, err := p.pool.Exec(ctx, `
		UPDATE egress_requests
		SET consumed_at = NOW()
		WHERE id = $1 AND status = 'approved' AND consumed_at IS NULL
	`, id)
	if err != nil {
		return fmt.Errorf("mark approval consumed: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound{Resource: "consumable_approval", ID: id}
	}
	return nil
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func scanEgressRequests(rows pgxRows) ([]domain.EgressRequest, error) {
	requests := make([]domain.EgressRequest, 0)
	for rows.Next() {
		var req domain.EgressRequest
		var status string
		if err := rows.Scan(
			&req.ID,
			&req.AgentID,
			&req.UserID,
			&req.OrgID,
			&req.Method,
			&req.Host,
			&req.Port,
			&req.Path,
			&req.Scheme,
			&status,
			&req.RuleID,
			&req.RequestedAt,
			&req.DecidedAt,
			&req.DecidedBy,
			&req.ErrorMessage,
			&req.ConsumedAt,
		); err != nil {
			return nil, fmt.Errorf("scan egress request: %w", err)
		}

		parsed, err := domain.ParseRequestStatus(status)
		if err != nil {
			return nil, err
		}
		req.Status = parsed
		requests = append(requests, req)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate egress requests: %w", err)
	}

	return requests, nil
}

type pgxRow interface {
	Scan(dest ...any) error
}

func scanEgressRequestRow(row pgxRow) (domain.EgressRequest, error) {
	var req domain.EgressRequest
	var status string
	if err := row.Scan(
		&req.ID,
		&req.AgentID,
		&req.UserID,
		&req.OrgID,
		&req.Method,
		&req.Host,
		&req.Port,
		&req.Path,
		&req.Scheme,
		&status,
		&req.RuleID,
		&req.RequestedAt,
		&req.DecidedAt,
		&req.DecidedBy,
		&req.ErrorMessage,
		&req.ConsumedAt,
	); err != nil {
		return domain.EgressRequest{}, err
	}

	parsed, err := domain.ParseRequestStatus(status)
	if err != nil {
		return domain.EgressRequest{}, err
	}
	req.Status = parsed
	return req, nil
}

func isNoRows(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}

func scanPolicyRules(rows pgxRows) ([]domain.PolicyRule, error) {
	rules := make([]domain.PolicyRule, 0)
	for rows.Next() {
		var rule domain.PolicyRule
		var scope string
		var effect string
		if err := rows.Scan(
			&rule.ID,
			&rule.OrgID,
			&scope,
			&rule.ScopeRefID,
			&effect,
			&rule.Host,
			&rule.Port,
			&rule.Method,
			&rule.PathPrefix,
			&rule.CreatedAt,
			&rule.CreatedBy,
			&rule.ExpiresAt,
		); err != nil {
			return nil, fmt.Errorf("scan policy rule: %w", err)
		}

		parsedScope, err := parseRuleScope(scope)
		if err != nil {
			return nil, err
		}
		parsedEffect, err := parseRuleEffect(effect)
		if err != nil {
			return nil, err
		}
		rule.Scope = parsedScope
		rule.Effect = parsedEffect
		rules = append(rules, rule)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policy rules: %w", err)
	}

	return rules, nil
}

type pgxRows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close()
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

func parseRuleScope(raw string) (domain.RuleScope, error) {
	switch domain.RuleScope(raw) {
	case domain.RuleScopeOrg, domain.RuleScopeUser, domain.RuleScopeAgent:
		return domain.RuleScope(raw), nil
	default:
		return "", domain.InvalidEnumError{Field: "rule_scope", Value: raw}
	}
}

func parseRuleEffect(raw string) (domain.RuleEffect, error) {
	switch domain.RuleEffect(raw) {
	case domain.RuleEffectAllow, domain.RuleEffectDeny:
		return domain.RuleEffect(raw), nil
	default:
		return "", domain.InvalidEnumError{Field: "rule_effect", Value: raw}
	}
}

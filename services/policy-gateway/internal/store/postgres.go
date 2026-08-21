package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
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
		SELECT er.id, er.agent_id, er.user_id, er.org_id, er.method, er.host, er.port, er.path, er.scheme,
		       er.status, er.rule_id, er.requested_at, er.decided_at, er.decided_by, er.error_message, er.consumed_at,
		       COALESCE(u.display_name, ''), COALESCE(ag.name, '')
		FROM egress_requests er
		LEFT JOIN actors u ON u.id = er.user_id
		LEFT JOIN agents ag ON ag.id = er.agent_id
		WHERE ($1 = '' OR er.status = $1)
		  AND ($2 = '' OR er.host ILIKE '%' || $2 || '%')
		  AND ($3 = '' OR er.user_id::text = $3)
		  AND ($4 = '' OR er.agent_id::text = $4)
		  AND ($5::timestamptz IS NULL OR er.requested_at >= $5)
		  AND ($6::timestamptz IS NULL OR er.requested_at <= $6)
		ORDER BY er.requested_at DESC
		LIMIT $7 OFFSET $8
	`
	status := ""
	if in.Status != nil {
		status = string(*in.Status)
	}
	limit, offset := normalizePage(in.Limit, in.Offset)
	rows, err := p.pool.Query(ctx, baseQuery, status, in.Host, in.UserID, in.AgentID, in.From, in.To, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("query egress requests: %w", err)
	}
	defer rows.Close()

	return scanEnrichedEgressRequests(rows)
}

// normalizePage applies the default/max limit and floors offset, shared by
// every paginated list endpoint (users, agents, rules, requests, audit).
func normalizePage(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func (p *Postgres) ListRules(ctx context.Context, in ListRulesInput) ([]domain.PolicyRule, error) {
	limit, offset := normalizePage(in.Limit, in.Offset)
	var active *bool
	if in.Active != nil {
		active = in.Active
	}
	rows, err := p.pool.Query(ctx, `
		SELECT r.id, r.org_id, r.scope, r.scope_ref_id, r.effect, r.host, r.port, r.method,
		       r.path_prefix, r.created_at, r.created_by, r.expires_at,
		       CASE r.scope
		         WHEN 'org' THEN COALESCE(o.name, '')
		         WHEN 'user' THEN COALESCE(u.display_name, '')
		         WHEN 'agent' THEN COALESCE(ag.name, '')
		         ELSE ''
		       END AS scope_display_name,
		       COALESCE(creator.display_name, '') AS created_by_display_name
		FROM policy_rules r
		LEFT JOIN organizations o ON r.scope = 'org' AND o.id = r.scope_ref_id
		LEFT JOIN actors u ON r.scope = 'user' AND u.id = r.scope_ref_id
		LEFT JOIN agents ag ON r.scope = 'agent' AND ag.id = r.scope_ref_id
		LEFT JOIN actors creator ON creator.id = r.created_by
		WHERE ($1 = '' OR r.scope = $1)
		  AND ($2 = '' OR r.scope_ref_id::text = $2)
		  AND ($3 = '' OR r.effect = $3)
		  AND ($4 = '' OR r.host ILIKE '%' || $4 || '%')
		  AND (
		    $5::boolean IS NULL
		    OR ($5 IS TRUE AND (r.expires_at IS NULL OR r.expires_at > NOW()))
		    OR ($5 IS FALSE AND r.expires_at IS NOT NULL AND r.expires_at <= NOW())
		  )
		ORDER BY r.created_at DESC
		LIMIT $6 OFFSET $7
	`, in.Scope, in.ScopeRefID, in.Effect, in.Host, active, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("query policy rules: %w", err)
	}
	defer rows.Close()

	rules := make([]domain.PolicyRule, 0)
	for rows.Next() {
		var rule domain.PolicyRule
		var scope, effect string
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
			&rule.ScopeDisplayName,
			&rule.CreatedByDisplayName,
		); err != nil {
			return nil, fmt.Errorf("scan policy rule: %w", err)
		}

		parsedScope, err := parseRuleScope(scope)
		if err != nil {
			continue
		}
		parsedEffect, err := parseRuleEffect(effect)
		if err != nil {
			continue
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

func (p *Postgres) ListAuditEvents(ctx context.Context, in ListAuditEventsInput) ([]domain.AuditEvent, error) {
	limit, offset := normalizePage(in.Limit, in.Offset)
	rows, err := p.pool.Query(ctx, `
		SELECT id, egress_request_id, event_type, actor_id, metadata_json, created_at
		FROM audit_events
		WHERE ($1 = '' OR event_type = $1)
		  AND ($2 = '' OR actor_id::text = $2)
		  AND ($3::timestamptz IS NULL OR created_at >= $3)
		  AND ($4::timestamptz IS NULL OR created_at <= $4)
		ORDER BY created_at DESC
		LIMIT $5 OFFSET $6
	`, in.EventType, in.ActorID, in.From, in.To, limit, offset)
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
		  AND starts_with($5, path_prefix)
		  AND (
		    length($5) = length(path_prefix)
		    OR substring($5 from length(path_prefix) + 1 for 1) = '/'
		  )
		  AND (expires_at IS NULL OR expires_at > NOW())
		  AND (
		    (scope = 'org' AND scope_ref_id = $1)
		    OR (scope = 'user' AND scope_ref_id = $6)
		    OR (scope = 'agent' AND scope_ref_id = $7)
		  )
		ORDER BY created_at ASC
	`, in.OrgID, in.Host, in.Port, in.Method, in.Path, in.UserID, in.AgentID)
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
	return p.insertAuditEvent(ctx, p.pool, egressRequestID, eventType, actorID, metadata)
}

func (p *Postgres) insertAuditEvent(ctx context.Context, exec queryExecutor, egressRequestID, eventType, actorID string, metadata map[string]any) error {
	payload, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("marshal audit metadata: %w", err)
	}

	_, err = exec.Exec(ctx, `
		INSERT INTO audit_events (egress_request_id, event_type, actor_id, metadata_json)
		VALUES ($1::uuid, $2, NULLIF($3, '')::uuid, $4::jsonb)
	`, nullIfEmpty(egressRequestID), eventType, actorID, string(payload))
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

type queryExecutor interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

func (p *Postgres) GetEgressRequest(ctx context.Context, id string) (domain.EgressRequest, error) {
	row := p.pool.QueryRow(ctx, `
		SELECT er.id, er.agent_id, er.user_id, er.org_id, er.method, er.host, er.port, er.path, er.scheme,
		       er.status, er.rule_id, er.requested_at, er.decided_at, er.decided_by, er.error_message, er.consumed_at,
		       COALESCE(u.display_name, ''), COALESCE(ag.name, '')
		FROM egress_requests er
		LEFT JOIN actors u ON u.id = er.user_id
		LEFT JOIN agents ag ON ag.id = er.agent_id
		WHERE er.id = $1
	`, id)

	req, err := scanEnrichedEgressRequestRow(row)
	if err != nil {
		if isNoRows(err) {
			return domain.EgressRequest{}, domain.ErrNotFound{Resource: "egress_request", ID: id}
		}
		return domain.EgressRequest{}, fmt.Errorf("get egress request: %w", err)
	}
	return req, nil
}

func (p *Postgres) ApproveRequestOnce(ctx context.Context, id, decidedBy string, audit AuditInput) (domain.EgressRequest, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return domain.EgressRequest{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	row := tx.QueryRow(ctx, `
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

	if err := p.insertAuditEvent(ctx, tx, audit.EgressRequestID, audit.EventType, audit.ActorID, enrichRequestAuditMetadata(audit.Metadata, req)); err != nil {
		return domain.EgressRequest{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.EgressRequest{}, fmt.Errorf("commit approve-once: %w", err)
	}
	return req, nil
}

func (p *Postgres) ApproveRequestWithScopedRule(ctx context.Context, id, decidedBy string, scope domain.RuleScope, scopeRefID string, opts OrgRuleOptions, audit AuditInput) (domain.EgressRequest, domain.PolicyRule, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return domain.EgressRequest{}, domain.PolicyRule{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var pending domain.EgressRequest
	var pendingStatus string
	err = tx.QueryRow(ctx, `
		SELECT id, agent_id, user_id, org_id, method, host, port, path, scheme,
		       status, rule_id, requested_at, decided_at, decided_by, error_message, consumed_at
		FROM egress_requests
		WHERE id = $1
		FOR UPDATE
	`, id).Scan(
		&pending.ID,
		&pending.AgentID,
		&pending.UserID,
		&pending.OrgID,
		&pending.Method,
		&pending.Host,
		&pending.Port,
		&pending.Path,
		&pending.Scheme,
		&pendingStatus,
		&pending.RuleID,
		&pending.RequestedAt,
		&pending.DecidedAt,
		&pending.DecidedBy,
		&pending.ErrorMessage,
		&pending.ConsumedAt,
	)
	if err != nil {
		if isNoRows(err) {
			return domain.EgressRequest{}, domain.PolicyRule{}, domain.ErrNotFound{Resource: "egress_request", ID: id}
		}
		return domain.EgressRequest{}, domain.PolicyRule{}, fmt.Errorf("load pending request: %w", err)
	}

	parsedStatus, err := domain.ParseRequestStatus(pendingStatus)
	if err != nil {
		return domain.EgressRequest{}, domain.PolicyRule{}, err
	}
	pending.Status = parsedStatus
	if pending.Status != domain.RequestStatusPending {
		return domain.EgressRequest{}, domain.PolicyRule{}, domain.ErrRequestNotPending{ID: id, Status: pending.Status}
	}

	var rule domain.PolicyRule
	rule, err = p.findOrInsertScopedAllowRuleTx(ctx, tx, pending, decidedBy, scope, scopeRefID, opts.ExpiresAt)
	if err != nil {
		return domain.EgressRequest{}, domain.PolicyRule{}, err
	}
	if _, err := p.incrementOrgPolicyVersionTx(ctx, tx, pending.OrgID); err != nil {
		return domain.EgressRequest{}, domain.PolicyRule{}, err
	}

	row := tx.QueryRow(ctx, `
		UPDATE egress_requests
		SET status = 'approved', decided_at = NOW(), decided_by = $2, rule_id = $3
		WHERE id = $1 AND status = 'pending'
		RETURNING id, agent_id, user_id, org_id, method, host, port, path, scheme,
		          status, rule_id, requested_at, decided_at, decided_by, error_message, consumed_at
	`, id, decidedBy, rule.ID)

	approved, err := scanEgressRequestRow(row)
	if err != nil {
		return domain.EgressRequest{}, domain.PolicyRule{}, fmt.Errorf("approve egress request with org rule: %w", err)
	}

	audit.Metadata = enrichRequestAuditMetadata(audit.Metadata, approved)
	audit.Metadata["rule_id"] = rule.ID
	audit.Metadata["path_prefix"] = rule.PathPrefix
	if rule.ExpiresAt != nil {
		audit.Metadata["expires_at"] = rule.ExpiresAt.UTC().Format(time.RFC3339)
	}

	if err := p.insertAuditEvent(ctx, tx, audit.EgressRequestID, audit.EventType, audit.ActorID, audit.Metadata); err != nil {
		return domain.EgressRequest{}, domain.PolicyRule{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.EgressRequest{}, domain.PolicyRule{}, fmt.Errorf("commit org rule approval: %w", err)
	}

	return approved, rule, nil
}

func (p *Postgres) DeletePolicyRule(ctx context.Context, id string, audit AuditInput) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var deletedOrgID string
	if err := tx.QueryRow(ctx, `DELETE FROM policy_rules WHERE id = $1 RETURNING org_id`, id).Scan(&deletedOrgID); err != nil {
		if isNoRows(err) {
			return domain.ErrNotFound{Resource: "policy_rule", ID: id}
		}
		return fmt.Errorf("delete policy rule: %w", err)
	}

	if _, err := p.incrementOrgPolicyVersionTx(ctx, tx, deletedOrgID); err != nil {
		return err
	}

	if err := p.insertAuditEvent(ctx, tx, audit.EgressRequestID, audit.EventType, audit.ActorID, audit.Metadata); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit rule revoke: %w", err)
	}
	return nil
}

func (p *Postgres) DenyRequest(ctx context.Context, id, decidedBy, feedback string, audit AuditInput) (domain.EgressRequest, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return domain.EgressRequest{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	row := tx.QueryRow(ctx, `
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

	if err := p.insertAuditEvent(ctx, tx, audit.EgressRequestID, audit.EventType, audit.ActorID, enrichRequestAuditMetadata(audit.Metadata, req)); err != nil {
		return domain.EgressRequest{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.EgressRequest{}, fmt.Errorf("commit deny: %w", err)
	}
	return req, nil
}

func enrichRequestAuditMetadata(metadata map[string]any, req domain.EgressRequest) map[string]any {
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["host"] = req.Host
	metadata["port"] = req.Port
	metadata["method"] = req.Method
	metadata["path"] = req.Path
	return metadata
}

func (p *Postgres) CreatePolicyRule(ctx context.Context, in CreatePolicyRuleInput, audit AuditInput) (domain.PolicyRule, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return domain.PolicyRule{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	rule, inserted, err := p.insertPolicyRuleTx(ctx, tx, in)
	if err != nil {
		return domain.PolicyRule{}, err
	}
	if !inserted {
		return domain.PolicyRule{}, domain.ErrRuleAlreadyExists{
			Host:       in.Host,
			Port:       in.Port,
			Method:     in.Method,
			PathPrefix: in.PathPrefix,
		}
	}
	if _, err := p.incrementOrgPolicyVersionTx(ctx, tx, in.OrgID); err != nil {
		return domain.PolicyRule{}, err
	}

	audit.Metadata = enrichRuleAuditMetadata(audit.Metadata, rule)
	if err := p.insertAuditEvent(ctx, tx, audit.EgressRequestID, audit.EventType, audit.ActorID, audit.Metadata); err != nil {
		return domain.PolicyRule{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.PolicyRule{}, fmt.Errorf("commit create policy rule: %w", err)
	}
	return rule, nil
}

func enrichRuleAuditMetadata(metadata map[string]any, rule domain.PolicyRule) map[string]any {
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["rule_id"] = rule.ID
	metadata["host"] = rule.Host
	metadata["port"] = rule.Port
	metadata["method"] = rule.Method
	metadata["path_prefix"] = rule.PathPrefix
	metadata["scope"] = rule.Scope
	metadata["effect"] = rule.Effect
	return metadata
}

func (p *Postgres) findOrInsertScopedAllowRuleTx(ctx context.Context, tx pgx.Tx, pending domain.EgressRequest, decidedBy string, scope domain.RuleScope, scopeRefID string, expiresAt *time.Time) (domain.PolicyRule, error) {
	in := CreatePolicyRuleInput{
		OrgID:      pending.OrgID,
		Scope:      scope,
		ScopeRefID: scopeRefID,
		Effect:     domain.RuleEffectAllow,
		Host:       pending.Host,
		Port:       pending.Port,
		Method:     pending.Method,
		PathPrefix: pending.Path,
		ExpiresAt:  expiresAt,
		CreatedBy:  decidedBy,
	}
	rule, _, err := p.insertPolicyRuleTx(ctx, tx, in)
	return rule, err
}

func (p *Postgres) insertPolicyRuleTx(ctx context.Context, tx pgx.Tx, in CreatePolicyRuleInput) (domain.PolicyRule, bool, error) {
	var rule domain.PolicyRule
	var scope string
	var effect string
	err := tx.QueryRow(ctx, `
		INSERT INTO policy_rules (
			org_id, scope, scope_ref_id, effect, host, port, method, path_prefix, created_by, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (org_id, scope, scope_ref_id, effect, host, port, method, path_prefix)
		DO NOTHING
		RETURNING id, org_id, scope, scope_ref_id, effect, host, port, method,
		          path_prefix, created_at, created_by, expires_at
	`, in.OrgID, string(in.Scope), in.ScopeRefID, string(in.Effect), in.Host, in.Port, in.Method, in.PathPrefix, in.CreatedBy, in.ExpiresAt).Scan(
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
	)
	if err == nil {
		finished, finishErr := finishPolicyRuleScan(rule, scope, effect)
		return finished, true, finishErr
	}
	if !isNoRows(err) {
		return domain.PolicyRule{}, false, fmt.Errorf("insert policy rule: %w", err)
	}

	row := tx.QueryRow(ctx, `
		SELECT id, org_id, scope, scope_ref_id, effect, host, port, method,
		       path_prefix, created_at, created_by, expires_at
		FROM policy_rules
		WHERE org_id = $1
		  AND scope = $2
		  AND scope_ref_id = $3
		  AND effect = $4
		  AND host = $5
		  AND port = $6
		  AND method = $7
		  AND path_prefix = $8
	`, in.OrgID, string(in.Scope), in.ScopeRefID, string(in.Effect), in.Host, in.Port, in.Method, in.PathPrefix)

	if err := row.Scan(
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
		return domain.PolicyRule{}, false, fmt.Errorf("load existing policy rule: %w", err)
	}
	finished, finishErr := finishPolicyRuleScan(rule, scope, effect)
	return finished, false, finishErr
}

func finishPolicyRuleScan(rule domain.PolicyRule, scope, effect string) (domain.PolicyRule, error) {
	parsedScope, err := parseRuleScope(scope)
	if err != nil {
		return domain.PolicyRule{}, err
	}
	parsedEffect, err := parseRuleEffect(effect)
	if err != nil {
		return domain.PolicyRule{}, err
	}
	rule.Scope = parsedScope
	rule.Effect = parsedEffect
	return rule, nil
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
		WHERE type != 'agent'
		  AND ($1 = '' OR status = $1)
		ORDER BY created_at ASC
		LIMIT $2 OFFSET $3
	`, in.Status, limit, offset)
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

func (p *Postgres) GetUser(ctx context.Context, id string) (domain.User, error) {
	row := p.pool.QueryRow(ctx, `
		SELECT id, org_id, display_name, email, role, status, external_subject, created_at, updated_at
		FROM actors
		WHERE id = $1 AND type != 'agent'
	`, id)

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

func (p *Postgres) UpdateUser(ctx context.Context, id string, in UpdateUserInput) (domain.User, error) {
	row := p.pool.QueryRow(ctx, `
		UPDATE actors
		SET display_name = COALESCE($2, display_name),
		    email = CASE WHEN $3::boolean THEN NULLIF($4, '') ELSE email END,
		    role = COALESCE($5, role),
		    status = COALESCE($6, status),
		    updated_at = NOW()
		WHERE id = $1 AND type != 'agent'
		RETURNING id, org_id, display_name, email, role, status, external_subject, created_at, updated_at
	`, id, in.DisplayName, in.Email != nil, derefString(in.Email), in.Role, in.Status)

	user, err := scanUserRow(row)
	if err != nil {
		if isNoRows(err) {
			return domain.User{}, domain.ErrNotFound{Resource: "user", ID: id}
		}
		return domain.User{}, fmt.Errorf("update user: %w", err)
	}
	return user, nil
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
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
		WHERE ($1 = '' OR ag.actor_id::text = $1)
		  AND ($2 = '' OR ag.status = $2)
		ORDER BY ag.created_at ASC
		LIMIT $3 OFFSET $4
	`, in.UserID, in.Status, limit, offset)
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

func (p *Postgres) GetAgent(ctx context.Context, id string) (domain.Agent, error) {
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
		return domain.Agent{}, fmt.Errorf("get agent: %w", err)
	}
	return agent, nil
}

func (p *Postgres) UpdateAgent(ctx context.Context, id string, in UpdateAgentInput) (domain.Agent, error) {
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
		WHERE id = $1
	`, id, in.Name, in.ContainerID != nil, in.ContainerID, hasMetadata, string(metadataJSON))
	if err != nil {
		return domain.Agent{}, fmt.Errorf("update agent: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.Agent{}, domain.ErrNotFound{Resource: "agent", ID: id}
	}

	return p.GetAgent(ctx, id)
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
	if err := p.insertAuditEvent(ctx, tx, audit.EgressRequestID, audit.EventType, audit.ActorID, audit.Metadata); err != nil {
		return domain.Agent{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.Agent{}, fmt.Errorf("commit register agent: %w", err)
	}

	return p.GetAgent(ctx, agentID)
}

func (p *Postgres) RevokeAgent(ctx context.Context, agentID string, audit AuditInput) (domain.Agent, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return domain.Agent{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx, `
		UPDATE agents
		SET status = 'revoked', revoked_at = NOW(), updated_at = NOW()
		WHERE id = $1 AND status != 'revoked'
	`, agentID)
	if err != nil {
		return domain.Agent{}, fmt.Errorf("revoke agent: %w", err)
	}
	if tag.RowsAffected() == 0 {
		if _, lookupErr := p.GetAgent(ctx, agentID); lookupErr != nil {
			return domain.Agent{}, lookupErr
		}
	}

	if _, err := tx.Exec(ctx, `
		UPDATE agent_credentials
		SET status = 'revoked', revoked_at = NOW()
		WHERE agent_id = $1 AND status = 'active'
	`, agentID); err != nil {
		return domain.Agent{}, fmt.Errorf("revoke agent credentials: %w", err)
	}

	audit.Metadata = enrichAgentAuditMetadata(audit.Metadata, agentID, "")
	if err := p.insertAuditEvent(ctx, tx, audit.EgressRequestID, audit.EventType, audit.ActorID, audit.Metadata); err != nil {
		return domain.Agent{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.Agent{}, fmt.Errorf("commit revoke agent: %w", err)
	}

	return p.GetAgent(ctx, agentID)
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

func (p *Postgres) CreateAgentCredential(ctx context.Context, in CreateAgentCredentialInput, audit AuditInput) (domain.AgentCredential, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return domain.AgentCredential{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	cred, err := p.insertAgentCredentialTx(ctx, tx, in)
	if err != nil {
		return domain.AgentCredential{}, err
	}

	audit.Metadata = enrichCredentialAuditMetadata(audit.Metadata, cred)
	if err := p.insertAuditEvent(ctx, tx, audit.EgressRequestID, audit.EventType, audit.ActorID, audit.Metadata); err != nil {
		return domain.AgentCredential{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.AgentCredential{}, fmt.Errorf("commit create agent credential: %w", err)
	}
	return cred, nil
}

func (p *Postgres) RotateAgentCredential(ctx context.Context, agentID string, in CreateAgentCredentialInput, audit AuditInput) (domain.AgentCredential, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return domain.AgentCredential{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		UPDATE agent_credentials
		SET status = 'revoked', revoked_at = NOW()
		WHERE agent_id = $1 AND status = 'active'
	`, agentID); err != nil {
		return domain.AgentCredential{}, fmt.Errorf("revoke prior agent credentials: %w", err)
	}

	in.AgentID = agentID
	cred, err := p.insertAgentCredentialTx(ctx, tx, in)
	if err != nil {
		return domain.AgentCredential{}, err
	}

	audit.Metadata = enrichCredentialAuditMetadata(audit.Metadata, cred)
	if err := p.insertAuditEvent(ctx, tx, audit.EgressRequestID, audit.EventType, audit.ActorID, audit.Metadata); err != nil {
		return domain.AgentCredential{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.AgentCredential{}, fmt.Errorf("commit rotate agent credential: %w", err)
	}
	return cred, nil
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

func enrichCredentialAuditMetadata(metadata map[string]any, cred domain.AgentCredential) map[string]any {
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["agent_id"] = cred.AgentID
	metadata["credential_id"] = cred.ID
	metadata["token_prefix"] = cred.TokenPrefix
	return metadata
}

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

func (p *Postgres) incrementOrgPolicyVersionTx(ctx context.Context, tx pgx.Tx, orgID string) (int64, error) {
	var version int64
	err := tx.QueryRow(ctx, `
		INSERT INTO organization_policy_versions (org_id, version)
		VALUES ($1, 1)
		ON CONFLICT (org_id) DO UPDATE
		SET version = organization_policy_versions.version + 1,
		    updated_at = NOW()
		RETURNING version
	`, orgID).Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("increment org policy version: %w", err)
	}
	return version, nil
}

func (p *Postgres) GetOrgPolicyVersion(ctx context.Context, orgID string) (int64, error) {
	var version int64
	err := p.pool.QueryRow(ctx, `
		SELECT version FROM organization_policy_versions WHERE org_id = $1
	`, orgID).Scan(&version)
	if err != nil {
		if isNoRows(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("get org policy version: %w", err)
	}
	return version, nil
}

func (p *Postgres) ListRulesForOrgSnapshot(ctx context.Context, orgID string) ([]domain.PolicyRule, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, org_id, scope, scope_ref_id, effect, host, port, method,
		       path_prefix, created_at, created_by, expires_at
		FROM policy_rules
		WHERE org_id = $1
		  AND (expires_at IS NULL OR expires_at > NOW())
		ORDER BY created_at ASC
	`, orgID)
	if err != nil {
		return nil, fmt.Errorf("query org policy snapshot rules: %w", err)
	}
	defer rows.Close()

	return scanPolicyRules(rows)
}

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
		          metadata_json, last_seen_at, created_at, revoked_at
	`, in.OrgID, in.Name, in.CredentialHash, in.CredentialPrefix, string(metadataJSON))

	gw, err := scanGatewayRow(row)
	if err != nil {
		return domain.Gateway{}, fmt.Errorf("register gateway: %w", err)
	}
	return gw, nil
}

func (p *Postgres) ListGateways(ctx context.Context, orgID string) ([]domain.Gateway, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, org_id, name, status, credential_prefix, credential_hash, version,
		       metadata_json, last_seen_at, created_at, revoked_at
		FROM gateways
		WHERE ($1 = '' OR org_id::text = $1)
		ORDER BY created_at ASC
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

func (p *Postgres) GetGateway(ctx context.Context, id string) (domain.Gateway, error) {
	row := p.pool.QueryRow(ctx, `
		SELECT id, org_id, name, status, credential_prefix, credential_hash, version,
		       metadata_json, last_seen_at, created_at, revoked_at
		FROM gateways
		WHERE id = $1
	`, id)

	gw, err := scanGatewayRow(row)
	if err != nil {
		if isNoRows(err) {
			return domain.Gateway{}, domain.ErrNotFound{Resource: "gateway", ID: id}
		}
		return domain.Gateway{}, fmt.Errorf("get gateway: %w", err)
	}
	return gw, nil
}

func (p *Postgres) GetGatewayByCredentialHash(ctx context.Context, credentialHash string) (domain.Gateway, error) {
	row := p.pool.QueryRow(ctx, `
		SELECT id, org_id, name, status, credential_prefix, credential_hash, version,
		       metadata_json, last_seen_at, created_at, revoked_at
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

func (p *Postgres) UpdateGatewayHeartbeat(ctx context.Context, id string, in GatewayHeartbeatInput) (domain.Gateway, error) {
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
		    metadata_json = CASE WHEN $4::boolean THEN $5::jsonb ELSE metadata_json END
		WHERE id = $1
	`, id, in.Version != "", in.Version, hasMetadata, string(metadataJSON))
	if err != nil {
		return domain.Gateway{}, fmt.Errorf("update gateway heartbeat: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.Gateway{}, domain.ErrNotFound{Resource: "gateway", ID: id}
	}

	return p.GetGateway(ctx, id)
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

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func scanEnrichedEgressRequests(rows pgxRows) ([]domain.EgressRequest, error) {
	requests := make([]domain.EgressRequest, 0)
	for rows.Next() {
		req, err := scanEnrichedEgressRequestRow(rows)
		if err != nil {
			return nil, fmt.Errorf("scan egress request: %w", err)
		}
		requests = append(requests, req)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate egress requests: %w", err)
	}

	return requests, nil
}

func scanEnrichedEgressRequestRow(row pgxRow) (domain.EgressRequest, error) {
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
		&req.UserDisplayName,
		&req.AgentDisplayName,
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

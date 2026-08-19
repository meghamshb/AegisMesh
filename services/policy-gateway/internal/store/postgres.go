package store

import (
	"context"
	"fmt"

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

func (p *Postgres) ListPendingRequests(ctx context.Context) ([]domain.EgressRequest, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, agent_id, user_id, org_id, method, host, port, path, scheme,
		       status, rule_id, requested_at, decided_at, decided_by, error_message
		FROM egress_requests
		WHERE status = 'pending'
		ORDER BY requested_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("query pending requests: %w", err)
	}
	defer rows.Close()

	requests := make([]domain.EgressRequest, 0)
	for rows.Next() {
		var req domain.EgressRequest
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
			&req.Status,
			&req.RuleID,
			&req.RequestedAt,
			&req.DecidedAt,
			&req.DecidedBy,
			&req.ErrorMessage,
		); err != nil {
			return nil, fmt.Errorf("scan pending request: %w", err)
		}
		requests = append(requests, req)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pending requests: %w", err)
	}

	return requests, nil
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

	rules := make([]domain.PolicyRule, 0)
	for rows.Next() {
		var rule domain.PolicyRule
		if err := rows.Scan(
			&rule.ID,
			&rule.OrgID,
			&rule.Scope,
			&rule.ScopeRefID,
			&rule.Effect,
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
		rules = append(rules, rule)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policy rules: %w", err)
	}

	return rules, nil
}

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
)

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
		WHERE r.org_id = $8
		  AND ($1 = '' OR r.scope = $1)
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
	`, in.Scope, in.ScopeRefID, in.Effect, in.Host, active, limit, offset, in.OrgID)
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
	if err := p.insertAuditEvent(ctx, tx, in.OrgID, audit.EgressRequestID, audit.EventType, audit.ActorID, audit.Metadata); err != nil {
		return domain.PolicyRule{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.PolicyRule{}, fmt.Errorf("commit create policy rule: %w", err)
	}
	return rule, nil
}

func (p *Postgres) DeletePolicyRule(ctx context.Context, orgID, id string, audit AuditInput) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var deletedOrgID string
	if err := tx.QueryRow(ctx, `
		DELETE FROM policy_rules WHERE id = $1 AND org_id = $2 RETURNING org_id
	`, id, orgID).Scan(&deletedOrgID); err != nil {
		if isNoRows(err) {
			return domain.ErrNotFound{Resource: "policy_rule", ID: id}
		}
		return fmt.Errorf("delete policy rule: %w", err)
	}

	if _, err := p.incrementOrgPolicyVersionTx(ctx, tx, deletedOrgID); err != nil {
		return err
	}

	if err := p.insertAuditEvent(ctx, tx, deletedOrgID, audit.EgressRequestID, audit.EventType, audit.ActorID, audit.Metadata); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit rule revoke: %w", err)
	}
	return nil
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

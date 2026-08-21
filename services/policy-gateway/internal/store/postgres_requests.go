package store

import (
	"context"
	"fmt"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
)

func (p *Postgres) ListRequests(ctx context.Context, in ListRequestsInput) ([]domain.EgressRequest, error) {
	baseQuery := `
		SELECT er.id, er.agent_id, er.user_id, er.org_id, er.method, er.host, er.port, er.path, er.scheme,
		       er.status, er.rule_id, er.requested_at, er.decided_at, er.decided_by, er.error_message, er.consumed_at,
		       COALESCE(u.display_name, ''), COALESCE(ag.name, '')
		FROM egress_requests er
		LEFT JOIN actors u ON u.id = er.user_id
		LEFT JOIN agents ag ON ag.id = er.agent_id
		WHERE er.org_id = $9
		  AND ($1 = '' OR er.status = $1)
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
	rows, err := p.pool.Query(ctx, baseQuery, status, in.Host, in.UserID, in.AgentID, in.From, in.To, limit, offset, in.OrgID)
	if err != nil {
		return nil, fmt.Errorf("query egress requests: %w", err)
	}
	defer rows.Close()

	return scanEnrichedEgressRequests(rows)
}

func (p *Postgres) GetEgressRequest(ctx context.Context, orgID, id string) (domain.EgressRequest, error) {
	row := p.pool.QueryRow(ctx, `
		SELECT er.id, er.agent_id, er.user_id, er.org_id, er.method, er.host, er.port, er.path, er.scheme,
		       er.status, er.rule_id, er.requested_at, er.decided_at, er.decided_by, er.error_message, er.consumed_at,
		       COALESCE(u.display_name, ''), COALESCE(ag.name, '')
		FROM egress_requests er
		LEFT JOIN actors u ON u.id = er.user_id
		LEFT JOIN agents ag ON ag.id = er.agent_id
		WHERE er.id = $1 AND er.org_id = $2
	`, id, orgID)

	req, err := scanEnrichedEgressRequestRow(row)
	if err != nil {
		if isNoRows(err) {
			return domain.EgressRequest{}, domain.ErrNotFound{Resource: "egress_request", ID: id}
		}
		return domain.EgressRequest{}, fmt.Errorf("get egress request: %w", err)
	}
	return req, nil
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

func (p *Postgres) ApproveRequestOnce(ctx context.Context, orgID, id, decidedBy string, audit AuditInput) (domain.EgressRequest, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return domain.EgressRequest{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	row := tx.QueryRow(ctx, `
		UPDATE egress_requests
		SET status = 'approved', decided_at = NOW(), decided_by = $2
		WHERE id = $1 AND org_id = $3 AND status = 'pending'
		RETURNING id, agent_id, user_id, org_id, method, host, port, path, scheme,
		          status, rule_id, requested_at, decided_at, decided_by, error_message, consumed_at
	`, id, decidedBy, orgID)

	req, err := scanEgressRequestRow(row)
	if err != nil {
		if isNoRows(err) {
			// Re-read within the caller's org: a request that exists but belongs
			// to another tenant must be indistinguishable from one that does not
			// exist at all.
			existing, lookupErr := p.GetEgressRequest(ctx, orgID, id)
			if lookupErr != nil {
				return domain.EgressRequest{}, domain.ErrNotFound{Resource: "egress_request", ID: id}
			}
			return domain.EgressRequest{}, domain.ErrRequestNotPending{ID: id, Status: existing.Status}
		}
		return domain.EgressRequest{}, fmt.Errorf("approve egress request: %w", err)
	}

	if err := p.insertAuditEvent(ctx, tx, req.OrgID, audit.EgressRequestID, audit.EventType, audit.ActorID, enrichRequestAuditMetadata(audit.Metadata, req)); err != nil {
		return domain.EgressRequest{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.EgressRequest{}, fmt.Errorf("commit approve-once: %w", err)
	}
	return req, nil
}

func (p *Postgres) ApproveRequestWithScopedRule(ctx context.Context, orgID, id, decidedBy string, scope domain.RuleScope, scopeRefID string, opts OrgRuleOptions, audit AuditInput) (domain.EgressRequest, domain.PolicyRule, error) {
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
		WHERE id = $1 AND org_id = $2
		FOR UPDATE
	`, id, orgID).Scan(
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
		WHERE id = $1 AND org_id = $4 AND status = 'pending'
		RETURNING id, agent_id, user_id, org_id, method, host, port, path, scheme,
		          status, rule_id, requested_at, decided_at, decided_by, error_message, consumed_at
	`, id, decidedBy, rule.ID, orgID)

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

	if err := p.insertAuditEvent(ctx, tx, approved.OrgID, audit.EgressRequestID, audit.EventType, audit.ActorID, audit.Metadata); err != nil {
		return domain.EgressRequest{}, domain.PolicyRule{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.EgressRequest{}, domain.PolicyRule{}, fmt.Errorf("commit org rule approval: %w", err)
	}

	return approved, rule, nil
}

func (p *Postgres) DenyRequest(ctx context.Context, orgID, id, decidedBy, feedback string, audit AuditInput) (domain.EgressRequest, error) {
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
		WHERE id = $1 AND org_id = $4 AND status = 'pending'
		RETURNING id, agent_id, user_id, org_id, method, host, port, path, scheme,
		          status, rule_id, requested_at, decided_at, decided_by, error_message, consumed_at
	`, id, decidedBy, feedback, orgID)

	req, err := scanEgressRequestRow(row)
	if err != nil {
		if isNoRows(err) {
			existing, lookupErr := p.GetEgressRequest(ctx, orgID, id)
			if lookupErr != nil {
				return domain.EgressRequest{}, domain.ErrNotFound{Resource: "egress_request", ID: id}
			}
			return domain.EgressRequest{}, domain.ErrRequestNotPending{ID: id, Status: existing.Status}
		}
		return domain.EgressRequest{}, fmt.Errorf("deny egress request: %w", err)
	}

	if err := p.insertAuditEvent(ctx, tx, req.OrgID, audit.EgressRequestID, audit.EventType, audit.ActorID, enrichRequestAuditMetadata(audit.Metadata, req)); err != nil {
		return domain.EgressRequest{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.EgressRequest{}, fmt.Errorf("commit deny: %w", err)
	}
	return req, nil
}

// FindConsumableApproval and HasDeniedPattern are data-plane lookups keyed on
// the authenticated agent. The org predicate is defence in depth: agent_id
// already implies an org, so a mismatch here means the caller's identity and
// the row disagree, and the safe answer is "no grant" / "no history".
func (p *Postgres) FindConsumableApproval(ctx context.Context, in ApprovalMatchInput) (*domain.EgressRequest, error) {
	row := p.pool.QueryRow(ctx, `
		SELECT id, agent_id, user_id, org_id, method, host, port, path, scheme,
		       status, rule_id, requested_at, decided_at, decided_by, error_message, consumed_at
		FROM egress_requests
		WHERE agent_id = $1
		  AND org_id = $6
		  AND host = $2
		  AND port = $3
		  AND method = $4
		  AND path = $5
		  AND status = 'approved'
		  AND consumed_at IS NULL
		ORDER BY decided_at DESC
		LIMIT 1
	`, in.AgentID, in.Host, in.Port, in.Method, in.Path, in.OrgID)

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
			  AND org_id = $6
			  AND host = $2
			  AND port = $3
			  AND method = $4
			  AND path = $5
			  AND status = 'denied'
		)
	`, in.AgentID, in.Host, in.Port, in.Method, in.Path, in.OrgID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check denied pattern: %w", err)
	}
	return exists, nil
}

func (p *Postgres) MarkApprovalConsumed(ctx context.Context, orgID, id string) error {
	tag, err := p.pool.Exec(ctx, `
		UPDATE egress_requests
		SET consumed_at = NOW()
		WHERE id = $1 AND org_id = $2 AND status = 'approved' AND consumed_at IS NULL
	`, id, orgID)
	if err != nil {
		return fmt.Errorf("mark approval consumed: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound{Resource: "consumable_approval", ID: id}
	}
	return nil
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

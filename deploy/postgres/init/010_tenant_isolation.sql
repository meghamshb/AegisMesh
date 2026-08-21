-- Tenant-isolation hardening (post-5.9 audit).
--
-- audit_events was the only tenant-owned table with no org_id at all, so
-- ListAuditEvents had nothing to filter on and returned every organization's
-- audit trail to any admin caller. Add the column, backfill it from the rows
-- that already carry an org, and index the read path.

ALTER TABLE audit_events
    ADD COLUMN IF NOT EXISTS org_id UUID;

-- Backfill: prefer the owning egress request's org, else the acting actor's.
UPDATE audit_events ae
SET org_id = er.org_id
FROM egress_requests er
WHERE ae.egress_request_id = er.id
  AND ae.org_id IS NULL;

UPDATE audit_events ae
SET org_id = a.org_id
FROM actors a
WHERE ae.actor_id = a.id
  AND ae.org_id IS NULL;

-- Any remaining row predates multi-org and cannot be attributed from its own
-- columns (no request, no actor). Those belong to the original single-tenant
-- deployment, so assign them the seeded default org rather than dropping audit
-- history or leaving rows that no tenant-scoped query could ever return.
UPDATE audit_events
SET org_id = '11111111-1111-1111-1111-111111111010'
WHERE org_id IS NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'audit_events_org_fk'
    ) THEN
        ALTER TABLE audit_events
            ADD CONSTRAINT audit_events_org_fk
            FOREIGN KEY (org_id)
            REFERENCES organizations(id);
    END IF;
END $$;

ALTER TABLE audit_events
    ALTER COLUMN org_id SET NOT NULL;

-- Indexes for the newly org-scoped read paths.
CREATE INDEX IF NOT EXISTS idx_audit_events_org_created
    ON audit_events (org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_egress_requests_org_requested
    ON egress_requests (org_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_policy_rules_org_created
    ON policy_rules (org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gateways_org ON gateways (org_id);

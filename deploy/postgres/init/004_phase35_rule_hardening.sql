-- Phase 3.5: prevent duplicate org rules and support ON CONFLICT dedup.
CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_rules_dedup
    ON policy_rules (org_id, scope, scope_ref_id, effect, host, port, method, path_prefix);

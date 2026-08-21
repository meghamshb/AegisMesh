-- Phase 5.9: gateway registration and central policy synchronization.
-- Gateways authenticate to the control plane with their own credential,
-- distinct from agent credentials (different trust domain), and fetch a
-- versioned, org-scoped policy snapshot.

CREATE TABLE IF NOT EXISTS gateways (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'revoked')),
    credential_hash TEXT NOT NULL UNIQUE,
    credential_prefix TEXT NOT NULL,
    version TEXT,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    UNIQUE (org_id, name)
);

CREATE INDEX IF NOT EXISTS idx_gateways_org ON gateways(org_id);

-- Policy version increments on every policy_rules mutation (create/revoke),
-- so a gateway's cached snapshot can tell whether it is current.
CREATE TABLE IF NOT EXISTS organization_policy_versions (
    org_id UUID PRIMARY KEY REFERENCES organizations(id),
    version BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

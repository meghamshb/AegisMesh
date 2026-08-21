-- Phase 5.3: agent registration and credential lifecycle.
-- Replaces "agent identity is a manually configured env var" with a real
-- registration object and an opaque, hashed credential. Does not change
-- proxy authentication (Phase 5.4).

CREATE TABLE IF NOT EXISTS agent_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    token_prefix TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'revoked')),
    created_by UUID REFERENCES actors(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_agent_credentials_agent
    ON agent_credentials(agent_id);

CREATE INDEX IF NOT EXISTS idx_agent_credentials_active
    ON agent_credentials(agent_id, status);

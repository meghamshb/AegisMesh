CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS actors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type TEXT NOT NULL CHECK (type IN ('user', 'agent', 'admin')),
    org_id UUID NOT NULL,
    display_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id UUID NOT NULL REFERENCES actors(id),
    container_id TEXT,
    name TEXT NOT NULL,
    last_seen_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS policy_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL,
    scope TEXT NOT NULL CHECK (scope IN ('org', 'user', 'agent')),
    scope_ref_id UUID NOT NULL,
    effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 443,
    method TEXT NOT NULL DEFAULT '*',
    path_prefix TEXT NOT NULL DEFAULT '/',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL REFERENCES actors(id),
    expires_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS egress_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES agents(id),
    user_id UUID NOT NULL REFERENCES actors(id),
    org_id UUID NOT NULL,
    method TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    path TEXT NOT NULL,
    scheme TEXT NOT NULL CHECK (scheme IN ('http', 'https')),
    status TEXT NOT NULL CHECK (
        status IN ('pending', 'approved', 'denied', 'auto_approved', 'expired')
    ),
    rule_id UUID REFERENCES policy_rules(id),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at TIMESTAMPTZ,
    decided_by UUID REFERENCES actors(id),
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    egress_request_id UUID REFERENCES egress_requests(id),
    event_type TEXT NOT NULL,
    actor_id UUID REFERENCES actors(id),
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_egress_requests_status ON egress_requests(status);
CREATE INDEX IF NOT EXISTS idx_egress_requests_host ON egress_requests(host);
CREATE INDEX IF NOT EXISTS idx_policy_rules_host ON policy_rules(host);
CREATE INDEX IF NOT EXISTS idx_policy_rules_lookup
    ON policy_rules (org_id, host, port, method);

-- For scope='org', scope_ref_id must equal org_id. Documented convention for Phase 1 evaluators.

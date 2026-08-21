-- Phase 5.10: fleet status reporting.
--
-- The Gateways tab shows which policy version each gateway is actually
-- enforcing and how many agents it has served recently. Both arrive on the
-- heartbeat (domain.GatewayHeartbeatBody already carried the fields; they had
-- nowhere to land), so give them real columns rather than burying them in
-- metadata_json where they cannot be indexed or ordered.

ALTER TABLE gateways
    ADD COLUMN IF NOT EXISTS policy_version BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS active_agents INTEGER NOT NULL DEFAULT 0;

-- The tab sorts by liveness within an org.
CREATE INDEX IF NOT EXISTS idx_gateways_org_last_seen
    ON gateways (org_id, last_seen_at DESC NULLS LAST);

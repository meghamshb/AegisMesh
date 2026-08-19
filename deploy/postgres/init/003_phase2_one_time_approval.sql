ALTER TABLE egress_requests
    ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_egress_requests_one_time_approval
    ON egress_requests (agent_id, host, port, method, path)
    WHERE status = 'approved' AND consumed_at IS NULL;

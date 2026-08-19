-- Fixed UUIDs for v1 single-agent Compose topology (one Hermes container = one identity).
INSERT INTO actors (id, type, org_id, display_name) VALUES
    ('11111111-1111-1111-1111-111111111001', 'user', '11111111-1111-1111-1111-111111111010', 'Default User'),
    ('11111111-1111-1111-1111-111111111002', 'admin', '11111111-1111-1111-1111-111111111010', 'Default Admin')
ON CONFLICT (id) DO NOTHING;

INSERT INTO agents (id, actor_id, name, container_id) VALUES
    ('11111111-1111-1111-1111-111111111020', '11111111-1111-1111-1111-111111111001', 'hermes-agent', 'hermes')
ON CONFLICT (id) DO NOTHING;

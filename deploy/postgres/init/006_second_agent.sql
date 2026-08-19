-- Second agent identity for cross-agent org-rule smoke tests (Phase 3.5).
INSERT INTO actors (id, type, org_id, display_name) VALUES
    ('11111111-1111-1111-1111-111111111003', 'user', '11111111-1111-1111-1111-111111111010', 'Second User')
ON CONFLICT (id) DO NOTHING;

INSERT INTO agents (id, actor_id, name, container_id) VALUES
    ('11111111-1111-1111-1111-111111111021', '11111111-1111-1111-1111-111111111003', 'hermes-agent-2', 'hermes')
ON CONFLICT (id) DO NOTHING;

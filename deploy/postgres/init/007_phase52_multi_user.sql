-- Phase 5.2: multi-user schema foundation.
-- Turns the existing ad-hoc org/user/agent IDs into a real, FK-backed,
-- tenant-aware identity model without changing Phase 0-4 behavior.

-- 5.2.1 Organizations -------------------------------------------------------

CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed the existing development org UUID so it becomes a valid FK target.
INSERT INTO organizations (id, slug, name)
VALUES (
    '11111111-1111-1111-1111-111111111010',
    'default',
    'Default Organization'
)
ON CONFLICT (id) DO NOTHING;

-- 5.2.2 Evolve actors into human principals ---------------------------------

ALTER TABLE actors
    ADD COLUMN IF NOT EXISTS email TEXT,
    ADD COLUMN IF NOT EXISTS role TEXT,
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active',
    ADD COLUMN IF NOT EXISTS external_subject TEXT,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

UPDATE actors
SET role = CASE WHEN type = 'admin' THEN 'admin' ELSE 'member' END
WHERE role IS NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'actors_role_check'
    ) THEN
        ALTER TABLE actors
            ADD CONSTRAINT actors_role_check
            CHECK (role IN ('admin', 'approver', 'member'));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'actors_status_check'
    ) THEN
        ALTER TABLE actors
            ADD CONSTRAINT actors_status_check
            CHECK (status IN ('active', 'disabled'));
    END IF;
END $$;

-- 5.2.3 Organization FK on actors -------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'actors_org_fk'
    ) THEN
        ALTER TABLE actors
            ADD CONSTRAINT actors_org_fk
            FOREIGN KEY (org_id)
            REFERENCES organizations(id);
    END IF;
END $$;

-- 5.2.4 Evolve agents ---------------------------------------------------

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS org_id UUID,
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active',
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb;

UPDATE agents a
SET org_id = owner.org_id
FROM actors owner
WHERE a.actor_id = owner.id
  AND a.org_id IS NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'agents_org_fk'
    ) THEN
        ALTER TABLE agents
            ADD CONSTRAINT agents_org_fk
            FOREIGN KEY (org_id)
            REFERENCES organizations(id);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'agents_status_check'
    ) THEN
        ALTER TABLE agents
            ADD CONSTRAINT agents_status_check
            CHECK (status IN ('active', 'revoked'));
    END IF;
END $$;

-- 5.2.5 Indexes ---------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_actors_org ON actors(org_id);
CREATE INDEX IF NOT EXISTS idx_actors_org_email ON actors(org_id, email);
CREATE INDEX IF NOT EXISTS idx_agents_org ON agents(org_id);
CREATE INDEX IF NOT EXISTS idx_agents_owner ON agents(actor_id);
CREATE INDEX IF NOT EXISTS idx_agents_org_status ON agents(org_id, status);

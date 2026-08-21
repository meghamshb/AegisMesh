-- Phase 5.13: OIDC identity linking.
--
-- actors.external_subject has existed since migration 007 but was never read
-- or written. It now carries "<issuer>#<subject>" for operators who sign in
-- through an identity provider, and is the lookup key on every authenticated
-- control-plane request.

-- Uniqueness is the security-relevant part, not the speed. Without it two
-- actors could claim the same external identity, and which one a login
-- resolved to would depend on row order - a silent privilege escalation if one
-- of them is an admin. Partial, because unlinked actors legitimately share
-- NULL.
CREATE UNIQUE INDEX IF NOT EXISTS idx_actors_external_subject
    ON actors (external_subject)
    WHERE external_subject IS NOT NULL;

-- Supports the just-in-time email linking path.
CREATE INDEX IF NOT EXISTS idx_actors_lower_email
    ON actors (lower(email))
    WHERE email IS NOT NULL;

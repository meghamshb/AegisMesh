-- Fix: a policy rule could never be revoked once it had auto-approved anything.
--
-- egress_requests.rule_id referenced policy_rules(id) with no ON DELETE action,
-- so the moment a rule approved a single request, DELETE FROM policy_rules
-- failed with a foreign-key violation and the revoke endpoint returned 500.
-- Revocation is a core control - "this rule was a mistake, turn it off now" -
-- and it was silently broken for exactly the rules that mattered most: the ones
-- actually carrying traffic.
--
-- ON DELETE SET NULL is the right semantic. The egress request is history and
-- must survive; what does not survive is the live pointer to a rule that no
-- longer exists. Attribution is not lost either way: audit_events already
-- records rule_id in its metadata for both policy_rule_created and
-- policy_rule_revoked, so "which rule approved this, and when was it revoked"
-- remains answerable from the audit trail.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'egress_requests_rule_id_fkey'
    ) THEN
        ALTER TABLE egress_requests
            DROP CONSTRAINT egress_requests_rule_id_fkey;
    END IF;

    ALTER TABLE egress_requests
        ADD CONSTRAINT egress_requests_rule_id_fkey
        FOREIGN KEY (rule_id)
        REFERENCES policy_rules(id)
        ON DELETE SET NULL;
END $$;

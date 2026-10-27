-- Preserve the existing test-volume revision history when adopting public.
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '30s';
SELECT pg_advisory_xact_lock(hashtext('aegaeon.integration.atlas-ledger'));
DO $$
BEGIN
    IF to_regclass('atlas_schema_revisions.atlas_schema_revisions') IS NOT NULL THEN
        IF to_regclass('public.atlas_schema_revisions') IS NOT NULL THEN
            RAISE EXCEPTION 'Both Atlas revision ledgers exist; refusing ambiguous history';
        END IF;
        ALTER TABLE atlas_schema_revisions.atlas_schema_revisions SET SCHEMA public;
    END IF;
END
$$;
COMMIT;

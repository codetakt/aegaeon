-- Run with all service readers and writers stopped and drained. Atlas owns the enclosing transaction.
-- Never choose credentials to revoke during an upgrade.
LOCK TABLE aegaeon.client_secrets IN ACCESS EXCLUSIVE MODE;
DO $$
DECLARE
    missing record;
    free_slot smallint;
BEGIN
    IF EXISTS (
        SELECT 1 FROM aegaeon.client_secrets
        WHERE status = 'ACTIVE'
        GROUP BY client_id HAVING count(*) > 2
    ) THEN
        RAISE EXCEPTION 'client secret upgrade requires explicit resolution of clients with more than two ACTIVE credentials';
    END IF;
    FOR missing IN
        SELECT id, client_id FROM aegaeon.client_secrets
        WHERE status = 'ACTIVE' AND active_slot IS NULL
        ORDER BY client_id, id
    LOOP
        SELECT min(slot)::smallint INTO free_slot
        FROM generate_series(1, 2) AS slot
        WHERE NOT EXISTS (
            SELECT 1 FROM aegaeon.client_secrets existing
            WHERE existing.client_id = missing.client_id
              AND existing.status = 'ACTIVE' AND existing.active_slot = slot
        );
        IF free_slot IS NULL THEN
            RAISE EXCEPTION 'client secret active slot allocation failed';
        END IF;
        UPDATE aegaeon.client_secrets SET active_slot = free_slot WHERE id = missing.id;
    END LOOP;
END;
$$;
ALTER TABLE aegaeon.client_secrets
    ADD CONSTRAINT client_secrets_active_slot_required
    CHECK (status <> 'ACTIVE' OR active_slot IS NOT NULL);

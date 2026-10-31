-- Explicit domain operator capabilities. No existing principal gains access.
-- Apply together with the forward physical catalog while runtimes are drained.
DO $installation$
BEGIN
  IF pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE')
    OR pg_catalog.has_table_privilege('aegaeon_subject_owner','aegaeon.administrators','REFERENCES') THEN
    RAISE EXCEPTION 'unexpected preexisting operator installation privilege';
  END IF;
END
$installation$;
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
GRANT REFERENCES ON aegaeon.administrators TO aegaeon_subject_owner;
DO $installation$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
EXECUTE $ddl$
CREATE TABLE aegaeon.organization_operator_grants (
    id uuid PRIMARY KEY,
    environment_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    administrator_id uuid NOT NULL REFERENCES aegaeon.administrators(id),
    active boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    capabilities jsonb NOT NULL CHECK (jsonb_typeof(capabilities) = 'array'
        AND jsonb_array_length(capabilities) BETWEEN 1 AND 5
        AND capabilities <@ '["configure","provision","reconcile","export","support"]'),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (environment_id, domain_id, administrator_id),
    FOREIGN KEY (environment_id, domain_id)
        REFERENCES aegaeon.authorization_domains(environment_id, id)
);
ALTER TABLE aegaeon.organization_authority_events
    ALTER COLUMN organization_id DROP NOT NULL,
    ADD CONSTRAINT organization_authority_event_scope CHECK (
        (organization_id IS NULL AND event_type LIKE 'domain.%')
        OR (organization_id IS NOT NULL AND event_type NOT LIKE 'domain.%')
    );
$ddl$;
RESET ROLE;
END
$installation$;
REVOKE REFERENCES ON aegaeon.administrators FROM aegaeon_subject_owner;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;

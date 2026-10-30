-- Retained client registration identities; no automatic activation or grants.
-- Apply with the successor catalog while all runtimes are stopped and drained.
DO $installation$
BEGIN
  IF pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE') THEN
    RAISE EXCEPTION 'unexpected preexisting client-setting installation privilege';
  END IF;
END
$installation$;
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
DO $installation$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
EXECUTE $ddl$
CREATE TABLE aegaeon.organization_client_bindings (
    id uuid PRIMARY KEY,
    environment_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    client_registration_id uuid NOT NULL,
    client_identifier text COLLATE "C" NOT NULL
        CHECK (octet_length(client_identifier) BETWEEN 1 AND 255),
    active boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    targets jsonb NOT NULL CHECK (jsonb_typeof(targets) = 'array'
        AND jsonb_array_length(targets) BETWEEN 1 AND 32
        AND octet_length(targets::text) <= 65536),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT organization_client_binding_registration
        UNIQUE (environment_id, domain_id, client_registration_id),
    FOREIGN KEY (environment_id, domain_id)
        REFERENCES aegaeon.authorization_domains(environment_id, id)
);
$ddl$;
RESET ROLE;
END
$installation$;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;

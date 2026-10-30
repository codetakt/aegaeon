-- ORG-R02 / ORG-G02 / ORG-P02, ORG-P13: permanent membership history.
-- Stop and drain all runtimes. Apply this and the catalog successor together.
DO $installation$
BEGIN
  IF pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE')
    OR pg_catalog.has_table_privilege('aegaeon_subject_owner','aegaeon.environments','REFERENCES') THEN
    RAISE EXCEPTION 'unexpected preexisting organization installation privilege';
  END IF;
END
$installation$;
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
GRANT REFERENCES ON aegaeon.environments TO aegaeon_subject_owner;
DO $installation$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
EXECUTE $ddl$
-- Optional native organization authority. Existing environments gain no grants.
-- Durable IDs and tombstones are preserved independently of profile attributes.

CREATE TABLE aegaeon.authorization_domains (
    id uuid PRIMARY KEY,
    environment_id uuid NOT NULL REFERENCES aegaeon.environments(id),
    name text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 256),
    is_default boolean NOT NULL DEFAULT false,
    enabled boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    UNIQUE (environment_id, id)
);
CREATE UNIQUE INDEX authorization_domains_one_default
    ON aegaeon.authorization_domains(environment_id) WHERE is_default;

CREATE TABLE aegaeon.authorization_domain_targets (
    environment_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    audience text COLLATE "C" NOT NULL CHECK (octet_length(audience) BETWEEN 1 AND 2048),
    management boolean NOT NULL DEFAULT false,
    PRIMARY KEY (environment_id, audience),
    FOREIGN KEY (environment_id, domain_id)
        REFERENCES aegaeon.authorization_domains(environment_id, id)
);

CREATE TABLE aegaeon.application_organizations (
    id uuid PRIMARY KEY,
    environment_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    external_id text COLLATE "C" NOT NULL CHECK (octet_length(external_id) BETWEEN 1 AND 256
        AND external_id !~ '[[:cntrl:]]'),
    state text NOT NULL CHECK (state IN ('provisioning', 'active', 'suspended', 'deleted')),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    grant_generation bigint NOT NULL DEFAULT 1 CHECK (grant_generation > 0),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (environment_id, domain_id, id),
    UNIQUE (environment_id, domain_id, external_id),
    FOREIGN KEY (environment_id, domain_id)
        REFERENCES aegaeon.authorization_domains(environment_id, id)
);

CREATE TABLE aegaeon.organization_role_definitions (
    environment_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    role_key text COLLATE "C" NOT NULL CHECK (role_key ~ '^[A-Za-z0-9._:-]{1,128}$'),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    privileges jsonb NOT NULL CHECK (jsonb_typeof(privileges) = 'array'
        AND jsonb_array_length(privileges) BETWEEN 1 AND 256),
    manages_members boolean NOT NULL DEFAULT false,
    assignable_roles jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(assignable_roles) = 'array'
        AND jsonb_array_length(assignable_roles) <= 64
        AND (manages_members OR assignable_roles = '[]')),
    PRIMARY KEY (environment_id, domain_id, role_key),
    FOREIGN KEY (environment_id, domain_id)
        REFERENCES aegaeon.authorization_domains(environment_id, id)
);

CREATE TABLE aegaeon.organization_memberships (
    environment_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    end_user_id uuid NOT NULL,
    incarnation uuid NOT NULL,
    state text NOT NULL CHECK (state IN ('invited', 'active', 'suspended', 'removed')),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    grant_generation bigint NOT NULL DEFAULT 1 CHECK (grant_generation > 0),
    roles jsonb NOT NULL CHECK (jsonb_typeof(roles) = 'array' AND jsonb_array_length(roles) <= 64),
    PRIMARY KEY (environment_id, domain_id, organization_id, end_user_id),
    FOREIGN KEY (environment_id, domain_id, organization_id)
        REFERENCES aegaeon.application_organizations(environment_id, domain_id, id),
    FOREIGN KEY (end_user_id, environment_id)
        REFERENCES aegaeon.end_user_identity_owners(owner_id, environment_id)
);

-- Audit payload and the delivery obligation commit with each authority mutation.
-- Delivery state is separate so dispatch never rewrites an audit record.
CREATE TABLE aegaeon.organization_authority_events (
    id uuid PRIMARY KEY,
    environment_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    actor_id uuid NOT NULL,
    actor_kind text NOT NULL CHECK (actor_kind IN ('operator', 'member')),
    client_id text NOT NULL CHECK (octet_length(client_id) BETWEEN 1 AND 255),
    client_registration_id uuid,
    request_id text NOT NULL CHECK (octet_length(request_id) BETWEEN 1 AND 255),
    reason text NOT NULL CHECK (octet_length(reason) BETWEEN 1 AND 1024),
    event_type text NOT NULL,
    data jsonb NOT NULL CHECK (jsonb_typeof(data) = 'object'),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    FOREIGN KEY (environment_id, domain_id, organization_id)
        REFERENCES aegaeon.application_organizations(environment_id, domain_id, id)
);
CREATE TABLE aegaeon.organization_authority_outbox (
    event_id uuid PRIMARY KEY REFERENCES aegaeon.organization_authority_events(id),
    delivered_at timestamptz,
    attempts bigint NOT NULL DEFAULT 0 CHECK (attempts >= 0)
);

-- Retain receipts with the authority history; do not expire them with a cache.
CREATE TABLE aegaeon.organization_authority_receipts (
    environment_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    actor_id uuid NOT NULL,
    actor_kind text NOT NULL CHECK (actor_kind IN ('operator', 'member')),
    client_id text NOT NULL,
    client_registration_id uuid NOT NULL,
    operation text NOT NULL,
    idempotency_key text COLLATE "C" NOT NULL CHECK (octet_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    result jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (environment_id, domain_id, actor_id, actor_kind, client_id, client_registration_id, operation, idempotency_key),
    FOREIGN KEY (environment_id, domain_id)
        REFERENCES aegaeon.authorization_domains(environment_id, id)
);

$ddl$;
RESET ROLE;
END
$installation$;
REVOKE REFERENCES ON aegaeon.environments FROM aegaeon_subject_owner;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;

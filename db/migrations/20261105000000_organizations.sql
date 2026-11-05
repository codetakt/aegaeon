-- Organizations: one transactional upgrade from the pre-PR database.
-- Baseline: 46eaed0497fc2005cc10dc483803c108df68865b (24 published migrations).
-- Stop/drain application writers before this coordinated schema/runtime upgrade.

-- BEGIN ORGANIZATIONS COMPONENT organization_authority
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
    external_id text COLLATE "C" NOT NULL CHECK (octet_length(external_id) >= 1 AND octet_length(external_id) <= 256
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

-- END ORGANIZATIONS COMPONENT organization_authority

-- BEGIN ORGANIZATIONS COMPONENT organization_operator_authority
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

-- END ORGANIZATIONS COMPONENT organization_operator_authority

-- BEGIN ORGANIZATIONS COMPONENT organization_client_settings
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

-- END ORGANIZATIONS COMPONENT organization_client_settings

-- BEGIN ORGANIZATIONS COMPONENT organization_introspection_recipients
-- Explicit target-scoped resource server identities. No implicit recipient.
-- Apply with the successor catalog while all runtimes are stopped and drained.
DO $installation$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
ALTER TABLE aegaeon.authorization_domain_targets
  ADD COLUMN introspection_clients jsonb NOT NULL DEFAULT '[]'::jsonb
  CHECK (jsonb_typeof(introspection_clients) = 'array'
    AND jsonb_array_length(introspection_clients) <= 8
    AND octet_length(introspection_clients::text) <= 8192);
RESET ROLE;
END
$installation$;

-- END ORGANIZATIONS COMPONENT organization_introspection_recipients

-- BEGIN ORGANIZATIONS COMPONENT organization_invitations
-- Retained invitations and address challenges. Runtimes must be drained.
DO $installation$
BEGIN
  IF pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE') THEN
    RAISE EXCEPTION 'unexpected preexisting invitation installation privilege';
  END IF;
END
$installation$;
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
DO $installation$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
EXECUTE $ddl$
CREATE TABLE aegaeon.organization_invitations (
    id uuid PRIMARY KEY,
    environment_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','revoked','accepted')),
    recipient text COLLATE "C" NOT NULL CHECK (octet_length(recipient) BETWEEN 3 AND 254),
    authority jsonb NOT NULL CHECK (jsonb_typeof(authority)='object' AND octet_length(authority::text)<=65536),
    issued_at bigint NOT NULL CHECK (issued_at >= 0),
    expires_at bigint NOT NULL CHECK (expires_at > issued_at AND expires_at::numeric-issued_at::numeric BETWEEN 60 AND 86400),
    delivery_revision bigint NOT NULL DEFAULT 0 CHECK (delivery_revision BETWEEN 0 AND 5),
    delivered_at bigint,
    capability_hash bytea CHECK (octet_length(capability_hash)=32),
    accepted_challenge_id uuid,
    result jsonb CHECK (jsonb_typeof(result)='object' AND octet_length(result::text)<=16384),
    UNIQUE (environment_id, domain_id, id),
    FOREIGN KEY (environment_id, domain_id, organization_id)
        REFERENCES aegaeon.application_organizations(environment_id, domain_id, id),
    CHECK ((delivery_revision=0 AND delivered_at IS NULL AND capability_hash IS NULL)
        OR (delivery_revision>0 AND delivered_at IS NOT NULL AND capability_hash IS NOT NULL)),
    CHECK ((state='accepted')=(accepted_challenge_id IS NOT NULL AND result IS NOT NULL))
);
CREATE INDEX organization_invitations_domain_queue
    ON aegaeon.organization_invitations(environment_id,domain_id,state,issued_at,id);
CREATE TABLE aegaeon.organization_invitation_challenges (
    id uuid PRIMARY KEY,
    environment_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    invitation_id uuid NOT NULL,
    invitation_delivery_revision bigint NOT NULL CHECK (invitation_delivery_revision BETWEEN 1 AND 5),
    recipient_binding jsonb NOT NULL CHECK (jsonb_typeof(recipient_binding)='object' AND octet_length(recipient_binding::text)<=4096),
    request_key text COLLATE "C" NOT NULL CHECK (octet_length(request_key) BETWEEN 1 AND 128),
    issued_at bigint NOT NULL CHECK (issued_at >= 0),
    expires_at bigint NOT NULL CHECK (expires_at > issued_at AND expires_at::numeric-issued_at::numeric <= 300),
    delivery_revision bigint NOT NULL DEFAULT 0 CHECK (delivery_revision BETWEEN 0 AND 5),
    delivered_at bigint,
    capability_hash bytea CHECK (octet_length(capability_hash)=32),
    UNIQUE (environment_id,domain_id,invitation_id,request_key),
    FOREIGN KEY (environment_id,domain_id,invitation_id)
        REFERENCES aegaeon.organization_invitations(environment_id,domain_id,id),
    CHECK ((delivery_revision=0 AND delivered_at IS NULL AND capability_hash IS NULL)
        OR (delivery_revision>0 AND delivered_at IS NOT NULL AND capability_hash IS NOT NULL))
);
$ddl$;
RESET ROLE;
END
$installation$;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;

-- END ORGANIZATIONS COMPONENT organization_invitations

-- BEGIN ORGANIZATIONS COMPONENT organization_invitation_delivery
-- Stop and drain serving runtimes before changing the physical authority.
DO $migration$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
ALTER TABLE aegaeon.authorization_domains ADD COLUMN invitation_delivery jsonb
    CHECK (invitation_delivery IS NULL OR (jsonb_typeof(invitation_delivery)='object' AND octet_length(invitation_delivery::text)<=4096));
ALTER TABLE aegaeon.organization_invitations ADD COLUMN delivery_outcome text NOT NULL DEFAULT 'unclaimed'
    CHECK (delivery_outcome IN ('unclaimed','uncertain','acknowledged','rejected'));
ALTER TABLE aegaeon.organization_invitation_challenges ADD COLUMN delivery_outcome text NOT NULL DEFAULT 'unclaimed'
    CHECK (delivery_outcome IN ('unclaimed','uncertain','acknowledged','rejected'));
UPDATE aegaeon.organization_invitations SET delivery_outcome='uncertain' WHERE delivery_revision>0;
UPDATE aegaeon.organization_invitation_challenges SET delivery_outcome='uncertain' WHERE delivery_revision>0;
ALTER TABLE aegaeon.organization_invitations ADD CONSTRAINT organization_invitation_delivery_state
    CHECK ((delivery_revision=0)=(delivery_outcome='unclaimed'));
ALTER TABLE aegaeon.organization_invitation_challenges ADD CONSTRAINT organization_challenge_delivery_state
    CHECK ((delivery_revision=0)=(delivery_outcome='unclaimed'));
RESET ROLE;
END
$migration$;

-- END ORGANIZATIONS COMPONENT organization_invitation_delivery

-- BEGIN ORGANIZATIONS COMPONENT organization_identity_generation
-- ORG-R05/R06/R10/R14, ORG-G05/G07/G09: restoring ACTIVE never restores grants.
-- Drain serving processes before the complete forward migration/catalog stage.
ALTER TABLE aegaeon.end_users
  ADD COLUMN organization_identity_revision bigint NOT NULL DEFAULT 1
    CHECK (organization_identity_revision > 0),
  ADD COLUMN organization_reauthentication_after bigint NOT NULL DEFAULT 0
    CHECK (organization_reauthentication_after >= 0);

-- Historical authentication predating this new enforcement boundary cannot
-- supply a fresh Organizations approval. New user defaults remain zero.
UPDATE aegaeon.end_users SET organization_reauthentication_after =
  GREATEST(0, floor(extract(epoch FROM clock_timestamp()))::bigint);

CREATE FUNCTION aegaeon.organization_identity_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
  IF NEW.organization_identity_revision < OLD.organization_identity_revision
     OR NEW.organization_reauthentication_after < OLD.organization_reauthentication_after THEN
    RAISE EXCEPTION 'organization identity authority cannot roll back';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status OR NEW.subject IS DISTINCT FROM OLD.subject
     OR NEW.email IS DISTINCT FROM OLD.email THEN
    NEW.organization_identity_revision := GREATEST(NEW.organization_identity_revision,
      CASE WHEN OLD.organization_identity_revision < 9223372036854775807
        THEN OLD.organization_identity_revision + 1 ELSE OLD.organization_identity_revision END);
    NEW.organization_reauthentication_after := GREATEST(NEW.organization_reauthentication_after,
      OLD.organization_reauthentication_after, floor(extract(epoch FROM clock_timestamp()))::bigint);
  END IF;
  RETURN NEW;
END
$function$;

CREATE FUNCTION aegaeon.organization_identity_credential_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE affected uuid;
BEGIN
  IF TG_OP='UPDATE' THEN
    IF NEW.end_user_id IS DISTINCT FROM OLD.end_user_id THEN
      RAISE EXCEPTION 'password credential identity cannot be reassigned';
    END IF;
    IF NEW.password_hash IS NOT DISTINCT FROM OLD.password_hash
       AND NEW.status IS NOT DISTINCT FROM OLD.status THEN RETURN NEW; END IF;
  END IF;
  affected := CASE WHEN TG_OP='DELETE' THEN OLD.end_user_id ELSE NEW.end_user_id END;
  UPDATE aegaeon.end_users SET
    organization_identity_revision = CASE WHEN organization_identity_revision < 9223372036854775807
      THEN organization_identity_revision + 1 ELSE organization_identity_revision END,
    organization_reauthentication_after = GREATEST(organization_reauthentication_after,
      floor(extract(epoch FROM clock_timestamp()))::bigint)
    WHERE id=affected;
  RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END
$function$;

REVOKE ALL ON FUNCTION aegaeon.organization_identity_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION aegaeon.organization_identity_credential_guard() FROM PUBLIC;
CREATE TRIGGER organization_identity_guard BEFORE UPDATE ON aegaeon.end_users
  FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_identity_guard();
CREATE TRIGGER organization_identity_credential_guard
  AFTER INSERT OR UPDATE OR DELETE ON aegaeon.end_user_password_credentials
  FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_identity_credential_guard();

DO $installation$
BEGIN
  IF pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE') THEN
    RAISE EXCEPTION 'subject owner has preexisting schema CREATE; remediation required';
  END IF;
END
$installation$;
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.organization_identity_guard() OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.organization_identity_credential_guard() OWNER TO aegaeon_subject_owner;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;

-- END ORGANIZATIONS COMPONENT organization_identity_generation

-- BEGIN ORGANIZATIONS COMPONENT organization_identity_enrollment
-- ORG-R14 / ORG-G04/G09: explicit Environment policy and protected self-service.
ALTER TABLE aegaeon.environments
  ADD COLUMN organization_identity_policy jsonb,
  ADD COLUMN organization_identity_policy_revision bigint NOT NULL DEFAULT 1
    CHECK (organization_identity_policy_revision > 0),
  ADD CONSTRAINT organization_identity_policy_object CHECK
    (organization_identity_policy IS NULL OR jsonb_typeof(organization_identity_policy)='object');
ALTER TABLE aegaeon.end_user_profiles ADD COLUMN verified_delivery_address text COLLATE "C"
  CHECK (verified_delivery_address IS NULL OR octet_length(verified_delivery_address) BETWEEN 3 AND 254);

CREATE FUNCTION aegaeon.organization_identity_policy_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
  IF NEW.organization_identity_policy_revision < OLD.organization_identity_policy_revision THEN
    RAISE EXCEPTION 'organization identity policy cannot roll back';
  END IF;
  IF NEW.organization_identity_policy IS DISTINCT FROM OLD.organization_identity_policy THEN
    NEW.organization_identity_policy_revision := GREATEST(NEW.organization_identity_policy_revision,
      CASE WHEN OLD.organization_identity_policy_revision < 9223372036854775807
        THEN OLD.organization_identity_policy_revision + 1 ELSE OLD.organization_identity_policy_revision END);
  END IF;
  RETURN NEW;
END
$function$;
REVOKE ALL ON FUNCTION aegaeon.organization_identity_policy_guard() FROM PUBLIC;
CREATE TRIGGER organization_identity_policy_guard BEFORE UPDATE ON aegaeon.environments
  FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_identity_policy_guard();


CREATE FUNCTION aegaeon.organization_identity_profile_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE affected uuid;
BEGIN
  IF TG_OP='UPDATE' THEN
    IF NEW.end_user_id IS DISTINCT FROM OLD.end_user_id THEN
      RAISE EXCEPTION 'profile identity cannot be reassigned';
    END IF;
    IF NEW.verified_delivery_address IS NOT DISTINCT FROM OLD.verified_delivery_address
       AND NEW.email_verified IS NOT DISTINCT FROM OLD.email_verified THEN RETURN NEW; END IF;
  END IF;
  IF TG_OP='INSERT' AND NEW.verified_delivery_address IS NULL AND NOT NEW.email_verified THEN RETURN NEW; END IF;
  IF TG_OP='DELETE' AND OLD.verified_delivery_address IS NULL AND NOT OLD.email_verified THEN RETURN OLD; END IF;
  affected := CASE WHEN TG_OP='DELETE' THEN OLD.end_user_id ELSE NEW.end_user_id END;
  UPDATE aegaeon.end_users SET
    organization_identity_revision = CASE WHEN organization_identity_revision < 9223372036854775807
      THEN organization_identity_revision + 1 ELSE organization_identity_revision END,
    organization_reauthentication_after = GREATEST(organization_reauthentication_after,
      floor(extract(epoch FROM clock_timestamp()))::bigint)
    WHERE id=affected;
  RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END
$function$;
REVOKE ALL ON FUNCTION aegaeon.organization_identity_profile_guard() FROM PUBLIC;
CREATE TRIGGER organization_identity_profile_guard AFTER INSERT OR UPDATE OR DELETE ON aegaeon.end_user_profiles
  FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_identity_profile_guard();

DO $installation$
BEGIN
  IF pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE') THEN
    RAISE EXCEPTION 'subject owner has preexisting schema CREATE; remediation required';
  END IF;
END
$installation$;
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
DO $tables$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
EXECUTE $definition$
CREATE TABLE aegaeon.organization_identity_requests (
  id uuid PRIMARY KEY,
  environment_id uuid NOT NULL,
  domain_id uuid NOT NULL,
  invitation_id uuid NOT NULL,
  invitation_delivery_revision bigint NOT NULL CONSTRAINT organization_identity_invitation_revision_positive CHECK (invitation_delivery_revision > 0),
  policy_revision bigint NOT NULL CHECK (policy_revision > 0),
  purpose text NOT NULL CHECK (purpose IN ('registration','password_recovery')),
  request_key text COLLATE "C" NOT NULL CHECK (octet_length(request_key) BETWEEN 1 AND 128),
  request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
  target_user_id uuid,
  target_identity_revision bigint CHECK (target_identity_revision > 0),
  issued_at bigint NOT NULL CHECK (issued_at >= 0),
  expires_at bigint NOT NULL CHECK (expires_at > issued_at AND expires_at-issued_at <= 600),
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','completed')),
  result jsonb,
  delivery_revision bigint NOT NULL DEFAULT 0 CHECK (delivery_revision BETWEEN 0 AND 5),
  delivered_at bigint,
  delivery_outcome text NOT NULL DEFAULT 'unclaimed' CHECK (delivery_outcome IN ('unclaimed','uncertain','acknowledged','rejected')),
  capability_hash bytea CHECK (octet_length(capability_hash)=32),
  FOREIGN KEY(environment_id,domain_id,invitation_id)
    REFERENCES aegaeon.organization_invitations(environment_id,domain_id,id),
  UNIQUE(environment_id,domain_id,invitation_id,request_key),
  CHECK ((target_user_id IS NULL) = (target_identity_revision IS NULL)),
  CHECK ((state='pending' AND result IS NULL) OR (state='completed' AND jsonb_typeof(result)='object')),
  CHECK ((delivery_revision=0 AND delivered_at IS NULL AND capability_hash IS NULL AND delivery_outcome='unclaimed')
    OR (delivery_revision>0 AND delivered_at IS NOT NULL AND capability_hash IS NOT NULL AND delivery_outcome<>'unclaimed'))
);
CREATE INDEX organization_identity_requests_environment ON aegaeon.organization_identity_requests(environment_id,id);

REVOKE ALL ON TABLE aegaeon.organization_identity_requests FROM PUBLIC;
$definition$;
RESET ROLE;
END
$tables$;

DO $replacement$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;

RESET ROLE;
END
$replacement$;

ALTER FUNCTION aegaeon.organization_identity_profile_guard() OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.organization_identity_policy_guard() OWNER TO aegaeon_subject_owner;

REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;

-- END ORGANIZATIONS COMPONENT organization_identity_enrollment

-- BEGIN ORGANIZATIONS COMPONENT organization_support_policy
-- ORG-R12 / ORG-G08 / ORG-P09: absent policy never grants temporary support.
-- Stop and drain serving processes through the complete forward catalog stage.
DO $preflight$
BEGIN
  IF pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE') THEN
    RAISE EXCEPTION 'subject owner has preexisting schema CREATE; remediation required';
  END IF;
END
$preflight$;
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
DO $installation$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
EXECUTE $definition$
ALTER TABLE aegaeon.authorization_domains
  ADD COLUMN support_policy jsonb,
  ADD COLUMN support_policy_revision bigint NOT NULL DEFAULT 1 CHECK (support_policy_revision > 0),
  ADD CONSTRAINT organization_support_policy_object CHECK
    (support_policy IS NULL OR (jsonb_typeof(support_policy)='object' AND octet_length(support_policy::text)<=65536));
$definition$;
EXECUTE $definition$
CREATE FUNCTION aegaeon.organization_support_policy_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
  IF NEW.support_policy_revision < OLD.support_policy_revision THEN
    RAISE EXCEPTION 'organization support policy cannot roll back';
  END IF;
  IF NEW.support_policy IS DISTINCT FROM OLD.support_policy THEN
    IF OLD.support_policy_revision = 9223372036854775807 AND NEW.support_policy IS NOT NULL THEN
      RAISE EXCEPTION 'exhausted support policy cannot be enabled';
    END IF;
    NEW.support_policy_revision := GREATEST(NEW.support_policy_revision,
      CASE WHEN OLD.support_policy_revision < 9223372036854775807
        THEN OLD.support_policy_revision + 1 ELSE OLD.support_policy_revision END);
  END IF;
  RETURN NEW;
END
$function$;
$definition$;
REVOKE ALL ON FUNCTION aegaeon.organization_support_policy_guard() FROM PUBLIC;
CREATE TRIGGER organization_support_policy_guard BEFORE UPDATE ON aegaeon.authorization_domains
  FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_support_policy_guard();
RESET ROLE;
END
$installation$;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;

-- END ORGANIZATIONS COMPONENT organization_support_policy

-- BEGIN ORGANIZATIONS COMPONENT organization_admin_access
-- ORG-R12 / ORG-G08 / ORG-P09: explicit, short-lived and permanently revocable.
DO $preflight$
BEGIN
  IF pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE') THEN
    RAISE EXCEPTION 'subject owner has preexisting schema CREATE; remediation required';
  END IF;
END
$preflight$;
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
DO $installation$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
EXECUTE $definition$
CREATE TABLE aegaeon.organization_admin_access_grants (
  id uuid PRIMARY KEY,
  environment_id uuid NOT NULL,
  domain_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  user_id uuid NOT NULL,
  client_registration_id uuid NOT NULL,
  root_id text COLLATE "C" NOT NULL CHECK (octet_length(root_id) BETWEEN 1 AND 2048),
  authority jsonb NOT NULL CHECK (jsonb_typeof(authority)='object' AND octet_length(authority::text)<=65536),
  revision bigint NOT NULL DEFAULT 1 CHECK (revision IN (1,2)),
  active boolean NOT NULL DEFAULT true,
  issued_at bigint NOT NULL CHECK (issued_at > 0),
  expires_at bigint NOT NULL CHECK (expires_at > issued_at AND expires_at-issued_at<=300),
  creation_key text COLLATE "C" NOT NULL CHECK (octet_length(creation_key) BETWEEN 1 AND 128),
  request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
  revocation_key text COLLATE "C" CHECK (octet_length(revocation_key) BETWEEN 1 AND 128),
  revocation_digest bytea CHECK (octet_length(revocation_digest)=32),
  UNIQUE(environment_id,domain_id,user_id,client_registration_id,root_id,creation_key),
  FOREIGN KEY(environment_id,domain_id,organization_id) REFERENCES aegaeon.application_organizations(environment_id,domain_id,id),
  CHECK ((active AND revision=1 AND revocation_key IS NULL AND revocation_digest IS NULL)
    OR (NOT active AND revision=2 AND revocation_key IS NOT NULL AND revocation_digest IS NOT NULL))
);
$definition$;
EXECUTE $definition$
CREATE FUNCTION aegaeon.organization_admin_access_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'administrative grant history cannot be deleted'; END IF;
  IF (to_jsonb(NEW)-ARRAY['active','revision','revocation_key','revocation_digest']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['active','revision','revocation_key','revocation_digest']) THEN
    RAISE EXCEPTION 'administrative grant bindings and lifetime are immutable';
  END IF;
  IF NOT OLD.active OR NEW.active OR NEW.revision<>2 THEN
    RAISE EXCEPTION 'administrative grant can only be revoked once';
  END IF;
  RETURN NEW;
END
$function$;
$definition$;
REVOKE ALL ON FUNCTION aegaeon.organization_admin_access_guard() FROM PUBLIC;
CREATE TRIGGER organization_admin_access_guard BEFORE UPDATE OR DELETE ON aegaeon.organization_admin_access_grants
  FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_admin_access_guard();
RESET ROLE;
END
$installation$;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;

-- END ORGANIZATIONS COMPONENT organization_admin_access

-- BEGIN ORGANIZATIONS COMPONENT organization_snapshot_history
-- ORG-R17 / ORG-G10 / ORG-P11/P13: bounded scoped permanent history reads.
-- The HTTP caller separately checks current Export authority before disclosure.
-- Direct history-table privileges and all existing identifiers remain unchanged.
DO $preflight$
BEGIN
  IF pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE') THEN
    RAISE EXCEPTION 'subject owner has preexisting schema CREATE; remediation required';
  END IF;
END
$preflight$;
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
DO $installation$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
EXECUTE $definition$
CREATE FUNCTION aegaeon.organization_snapshot_history_v1(
  scope_environment uuid, scope_domain uuid, collection text, after_key text, page_limit integer
) RETURNS TABLE(row_key text, row_data text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
  IF scope_environment IS NULL OR scope_environment='00000000-0000-0000-0000-000000000000'
    OR scope_domain IS NULL OR scope_domain='00000000-0000-0000-0000-000000000000'
    OR collection IS NULL OR collection NOT IN ('owners','subject_history')
    OR page_limit IS NULL OR page_limit NOT BETWEEN 1 AND 10
    OR octet_length(after_key)>4096
    OR NOT EXISTS (SELECT FROM aegaeon.authorization_domains d
      WHERE d.environment_id=scope_environment AND d.id=scope_domain) THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid scoped snapshot history request';
  END IF;
  RETURN QUERY
    WITH owners AS (
      SELECT m.end_user_id AS id FROM aegaeon.organization_memberships m
        WHERE m.environment_id=scope_environment AND m.domain_id=scope_domain
      UNION SELECT r.target_user_id FROM aegaeon.organization_identity_requests r
        WHERE r.environment_id=scope_environment AND r.domain_id=scope_domain AND r.target_user_id IS NOT NULL
      UNION SELECT (r.result->>'userId')::uuid FROM aegaeon.organization_identity_requests r
        WHERE r.environment_id=scope_environment AND r.domain_id=scope_domain AND r.result IS NOT NULL
      UNION SELECT (c.recipient_binding->'binding'->>'user_id')::uuid FROM aegaeon.organization_invitation_challenges c
        WHERE c.environment_id=scope_environment AND c.domain_id=scope_domain
      UNION SELECT g.user_id FROM aegaeon.organization_admin_access_grants g
        WHERE g.environment_id=scope_environment AND g.domain_id=scope_domain
      UNION SELECT (e->>'userId')::uuid FROM aegaeon.authorization_domains d
        CROSS JOIN LATERAL jsonb_array_elements(d.support_policy->'entitlements') e
        WHERE d.environment_id=scope_environment AND d.id=scope_domain
      UNION SELECT (i.authority->'actor'->>'id')::uuid FROM aegaeon.organization_invitations i
        WHERE i.environment_id=scope_environment AND i.domain_id=scope_domain AND i.authority->'actor'->>'kind'='member'
      UNION SELECT e.actor_id FROM aegaeon.organization_authority_events e
        WHERE e.environment_id=scope_environment AND e.domain_id=scope_domain AND e.actor_kind='member'
      UNION SELECT r.actor_id FROM aegaeon.organization_authority_receipts r
        WHERE r.environment_id=scope_environment AND r.domain_id=scope_domain AND r.actor_kind='member'
    ), rows AS (
      SELECT v.owner_id::text AS key, to_jsonb(v)::text AS data FROM (
        SELECT o.owner_id,o.environment_id,o.recorded_at FROM aegaeon.end_user_identity_owners o
        WHERE collection='owners' AND o.environment_id=scope_environment AND o.owner_id IN (SELECT id FROM owners)
      ) v
      UNION ALL SELECT v.subject, to_jsonb(v)::text FROM (
        SELECT r.environment_id,r.subject,r.owner_id,r.recorded_at FROM aegaeon.end_user_subject_reservations r
        WHERE collection='subject_history' AND r.environment_id=scope_environment AND r.owner_id IN (SELECT id FROM owners)
      ) v
    )
    SELECT r.key, CASE WHEN octet_length(r.data)<=262144 THEN r.data ELSE NULL END
    FROM rows r WHERE after_key IS NULL OR r.key COLLATE "C">after_key COLLATE "C"
    ORDER BY r.key COLLATE "C" LIMIT page_limit;
END
$function$;
$definition$;
REVOKE ALL ON FUNCTION aegaeon.organization_snapshot_history_v1(uuid,uuid,text,text,integer) FROM PUBLIC;
RESET ROLE;
END
$installation$;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;

-- END ORGANIZATIONS COMPONENT organization_snapshot_history

-- BEGIN ORGANIZATIONS COMPONENT organization_import_target
-- ORG-R17/R18/R19: private, read-only target dependency inspection.
-- No import, activation, credential transfer or raw maintenance SELECT grants.
DO $preflight$
BEGIN
  IF pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE') THEN
    RAISE EXCEPTION 'subject owner has preexisting schema CREATE; remediation required';
  END IF;
END
$preflight$;
GRANT SELECT ON aegaeon.clients,aegaeon.administrators,aegaeon.team_memberships,aegaeon.teams TO aegaeon_subject_owner;
GRANT SELECT(end_user_id,status,password_hash) ON aegaeon.end_user_password_credentials TO aegaeon_subject_owner;
GRANT SELECT(id,environment_id,configuration_version_id,connection_identifier,connection_type,issuer_url,client_id,client_auth_method,status,deleted_at) ON aegaeon.connections TO aegaeon_subject_owner;
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
DO $installation$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
CREATE INDEX end_user_subject_reservations_owner_lookup ON aegaeon.end_user_subject_reservations(owner_id,environment_id,subject);
EXECUTE $definition$
CREATE FUNCTION aegaeon.organization_import_target_v1(
  scope_environment uuid, runtime_name text, collection text, lookup_keys jsonb
) RETURNS TABLE(row_key text, row_data text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
SET timezone = 'UTC' SET datestyle = 'ISO, YMD'
AS $function$
DECLARE schema_hash text;
BEGIN
  PERFORM aegaeon.subject_history_maintenance_actor();
  IF scope_environment IS NULL OR scope_environment='00000000-0000-0000-0000-000000000000'
    OR runtime_name IS NULL OR octet_length(runtime_name) NOT BETWEEN 1 AND 63
    OR collection IS NULL OR collection NOT IN ('catalog','namespace','environment_dependency','domain','owners','subject_history','identities','client_dependencies','connection_dependencies','operators','organizations','targets')
    OR lookup_keys IS NULL OR jsonb_typeof(lookup_keys)<>'array'
    OR pg_catalog.pg_is_in_recovery()
    OR current_setting('transaction_isolation')<>'repeatable read'
    OR current_setting('transaction_read_only')<>'on' THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid import target request';
  END IF;
  IF jsonb_array_length(lookup_keys)>10
    OR EXISTS(SELECT FROM jsonb_array_elements(lookup_keys) k WHERE jsonb_typeof(k)<>'string' OR octet_length(k#>>'{}') NOT BETWEEN 1 AND 4096)
    OR (SELECT count(*) FROM jsonb_array_elements(lookup_keys))<>(SELECT count(DISTINCT k) FROM jsonb_array_elements(lookup_keys) k) THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid import target keys';
  END IF;
  IF collection IN ('catalog','namespace') THEN
    IF jsonb_array_length(lookup_keys)<>0 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='unexpected catalog keys'; END IF;
    schema_hash:=aegaeon.subject_history_preflight(runtime_name);
    IF collection='catalog' THEN
      RETURN QUERY SELECT c.row_key,c.row_text FROM aegaeon.subject_history_physical_catalog(runtime_name) c
        WHERE c.row_key LIKE 'function:%' OR c.row_key LIKE 'atlas_revision:%'
          OR (c.row_key LIKE 'role:%' AND c.row_text::jsonb->>'rolname'='aegaeon_subject_owner');
    ELSE
      RETURN QUERY SELECT n.environment_id::text,jsonb_build_object('environment_id',n.environment_id,'issuer_host',n.issuer_host,'origin',n.origin,'contract_version',n.contract_version,'receipt_id',a.receipt_id,'schema_sha256',schema_hash)::text
        FROM aegaeon.subject_ownership_namespaces n JOIN aegaeon.subject_ownership_adoptions a
          ON a.environment_id=n.environment_id AND a.kind=n.origin
        WHERE n.environment_id=scope_environment AND n.contract_version=1;
    END IF;
    RETURN;
  END IF;
  IF jsonb_array_length(lookup_keys)=0 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='missing target keys'; END IF;
  IF collection IN ('domain','environment_dependency','owners','identities','client_dependencies','connection_dependencies','operators','organizations') AND EXISTS(
    SELECT FROM jsonb_array_elements_text(lookup_keys) k WHERE k !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR k='00000000-0000-0000-0000-000000000000') THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid target object key';
  END IF;
  RETURN QUERY WITH keys AS (SELECT k AS key, CASE WHEN collection IN ('domain','environment_dependency','owners','identities','client_dependencies','connection_dependencies','operators','organizations') THEN k::uuid ELSE NULL END AS id FROM jsonb_array_elements_text(lookup_keys) k), rows AS (
    SELECT e.id::text AS key,to_jsonb(v) AS data FROM aegaeon.environments e CROSS JOIN LATERAL (
      SELECT e.id,e.issuer_host,e.issuer_url,e.status,e.active_configuration_version_id,e.organization_identity_policy,e.organization_identity_policy_revision
    ) v WHERE collection='environment_dependency' AND e.id=scope_environment AND e.id IN (SELECT id FROM keys)
    UNION ALL SELECT d.id::text,to_jsonb(d) FROM aegaeon.authorization_domains d
      WHERE collection='domain' AND (d.id IN (SELECT id FROM keys) OR (d.environment_id=scope_environment AND d.is_default))
    UNION ALL SELECT o.owner_id::text,to_jsonb(o)||jsonb_build_object('history_count',(SELECT count(*) FROM aegaeon.end_user_subject_reservations r WHERE r.owner_id=o.owner_id),'current_identity_present',EXISTS(SELECT FROM aegaeon.end_users u WHERE u.id=o.owner_id))
      FROM aegaeon.end_user_identity_owners o WHERE collection='owners' AND o.owner_id IN (SELECT id FROM keys)
    UNION ALL SELECT r.subject,to_jsonb(r) FROM aegaeon.end_user_subject_reservations r
      WHERE collection='subject_history' AND r.environment_id=scope_environment AND r.subject COLLATE "C" IN (SELECT key COLLATE "C" FROM keys)
    UNION ALL SELECT u.id::text,to_jsonb(v)||jsonb_build_object('active_credentials',(SELECT count(*) FROM aegaeon.end_user_password_credentials p WHERE p.end_user_id=u.id AND p.status='ACTIVE'),
      'compatible_credentials',(SELECT count(*) FROM aegaeon.end_user_password_credentials p WHERE p.end_user_id=u.id AND p.status='ACTIVE' AND octet_length(p.password_hash)=97 AND p.password_hash ~ '^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]{21}[AQgw]\$[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]$'))
      FROM aegaeon.end_users u CROSS JOIN LATERAL (
        SELECT u.id,u.environment_id,u.subject,u.status,u.created_at,u.updated_at,u.organization_identity_revision,u.organization_reauthentication_after
      ) v WHERE collection='identities' AND u.id IN (SELECT id FROM keys)
    UNION ALL SELECT c.id::text,to_jsonb(v) FROM aegaeon.clients c CROSS JOIN LATERAL (
      SELECT c.id,c.environment_id,c.configuration_version_id,c.client_identifier,c.client_type,c.status,c.deleted_at,c.allowed_grant_types,c.allowed_scopes,c.dpop_bound_access_tokens,c.token_endpoint_authentication_method
    ) v WHERE collection='client_dependencies' AND c.id IN (SELECT id FROM keys)
    UNION ALL SELECT k.id::text,jsonb_build_object('id',k.id,'environment_id',scope_environment,'present',c.id IS NOT NULL,'configuration',CASE WHEN c.id IS NULL THEN NULL ELSE jsonb_build_object('id',c.id,'environment_id',c.environment_id,'configuration_version_id',c.configuration_version_id,'connection_identifier',c.connection_identifier,'connection_type',c.connection_type,'issuer_url',c.issuer_url,'client_id',c.client_id,'client_auth_method',c.client_auth_method,'status',c.status,'deleted_at',c.deleted_at) END)
      FROM keys k LEFT JOIN aegaeon.connections c ON c.id=k.id WHERE collection='connection_dependencies'
    UNION ALL SELECT a.id::text,jsonb_build_object('id',a.id,'human_member',a.status='ACTIVE' AND a.kind='HUMAN' AND t.status='ACTIVE' AND n.status='ACTIVE' AND e.status='ACTIVE')
      FROM aegaeon.administrators a JOIN aegaeon.team_memberships m ON m.administrator_id=a.id
      JOIN aegaeon.teams t ON t.id=m.team_id JOIN aegaeon.tenants n ON n.team_id=t.id
      JOIN aegaeon.environments e ON e.tenant_id=n.id
      WHERE collection='operators' AND e.id=scope_environment AND a.id IN (SELECT id FROM keys)
    UNION ALL SELECT o.id::text,jsonb_build_object('id',o.id) FROM aegaeon.application_organizations o
      WHERE collection='organizations' AND o.id IN (SELECT id FROM keys)
    UNION ALL SELECT t.audience,jsonb_build_object('domain_id',t.domain_id) FROM aegaeon.authorization_domain_targets t
      WHERE collection='targets' AND t.environment_id=scope_environment AND t.audience COLLATE "C" IN (SELECT key COLLATE "C" FROM keys)
  ) SELECT r.key,CASE WHEN octet_length(r.data::text)<=262144 THEN r.data::text ELSE NULL END FROM rows r ORDER BY r.key COLLATE "C";
END
$function$;
$definition$;
REVOKE ALL ON FUNCTION aegaeon.organization_import_target_v1(uuid,text,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aegaeon.organization_import_target_v1(uuid,text,text,jsonb) TO aegaeon_subject_maintenance;
RESET ROLE;
END
$installation$;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;

-- END ORGANIZATIONS COMPONENT organization_import_target

-- BEGIN ORGANIZATIONS COMPONENT organization_inactive_import
-- ORG-R18/R19: maintenance-only inactive preparation. No activation entrypoint.
DO $preflight$
BEGIN
 IF pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE') OR pg_catalog.has_table_privilege('aegaeon_subject_owner','aegaeon.environments','REFERENCES') THEN
  RAISE EXCEPTION 'subject owner has preexisting schema CREATE';
 END IF;
END
$preflight$;
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
GRANT REFERENCES ON aegaeon.environments TO aegaeon_subject_owner;
DO $installation$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
ALTER TABLE aegaeon.authorization_domains ADD COLUMN import_operation_id uuid;
ALTER TABLE aegaeon.authorization_domains ADD CONSTRAINT organization_import_inactive CHECK (import_operation_id IS NULL OR NOT enabled);

CREATE TABLE aegaeon.organization_import_operations (
 id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'),
 environment_id uuid NOT NULL,
 domain_id uuid NOT NULL,
 source_sha256 text COLLATE "C" NOT NULL CHECK(source_sha256 ~ '^[0-9a-f]{64}$'),
 source_enabled boolean NOT NULL,
 session_actor name NOT NULL,
 maintenance_actor name NOT NULL,
 state text NOT NULL CHECK(state IN ('writing','prepared')),
 receipt jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object' AND octet_length(receipt::text)<=32768),
 created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
 UNIQUE(environment_id,domain_id),
 FOREIGN KEY(environment_id) REFERENCES aegaeon.environments(id)
);
REVOKE ALL ON aegaeon.organization_import_operations FROM PUBLIC;
EXECUTE $definition$
CREATE FUNCTION aegaeon.organization_import_hold_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE old_row jsonb; new_row jsonb; candidate jsonb; held boolean;
BEGIN
 IF current_user='aegaeon_subject_owner' THEN
  IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
 END IF;
 IF TG_OP<>'INSERT' THEN old_row:=to_jsonb(OLD); END IF;
 IF TG_OP<>'DELETE' THEN new_row:=to_jsonb(NEW); END IF;
 FOREACH candidate IN ARRAY ARRAY[old_row,new_row] LOOP
  IF candidate IS NULL THEN CONTINUE; END IF;
  IF TG_TABLE_NAME='authorization_domains' THEN
   held:=candidate->>'import_operation_id' IS NOT NULL;
  ELSIF TG_TABLE_NAME='organization_authority_outbox' THEN
   SELECT EXISTS(SELECT FROM aegaeon.organization_authority_events e JOIN aegaeon.authorization_domains d ON d.id=e.domain_id AND d.environment_id=e.environment_id WHERE e.id=(candidate->>'event_id')::uuid AND d.import_operation_id IS NOT NULL) INTO held;
  ELSE
   SELECT EXISTS(SELECT FROM aegaeon.authorization_domains d WHERE d.id=(candidate->>'domain_id')::uuid AND d.environment_id=(candidate->>'environment_id')::uuid AND d.import_operation_id IS NOT NULL) INTO held;
  END IF;
  IF held THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='inactive import cannot be changed by normal authority'; END IF;
 END LOOP;
 IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END
$function$;
$definition$;
EXECUTE $definition$
CREATE FUNCTION aegaeon.organization_import_operation_v1(operation_id uuid, scope_environment uuid, scope_domain uuid, source_digest text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE previous aegaeon.organization_import_operations%ROWTYPE;
BEGIN
 PERFORM aegaeon.subject_history_maintenance_actor();
 SELECT * INTO previous FROM aegaeon.organization_import_operations WHERE id=operation_id;
 IF NOT FOUND THEN RETURN NULL; END IF;
 IF previous.environment_id IS DISTINCT FROM scope_environment OR previous.domain_id IS DISTINCT FROM scope_domain OR previous.source_sha256 IS DISTINCT FROM source_digest OR previous.state<>'prepared' THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='import operation replay conflicts';
 END IF;
 RETURN previous.receipt;
END
$function$;
$definition$;
EXECUTE $definition$
CREATE FUNCTION aegaeon.organization_import_begin_v1(operation_id uuid, scope_environment uuid, scope_domain uuid, source_digest text, source_domain jsonb, inspection jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET timezone = 'UTC' SET datestyle = 'ISO, YMD'
AS $function$
BEGIN
 PERFORM aegaeon.subject_history_maintenance_actor();
 IF pg_is_in_recovery() OR current_setting('transaction_read_only')<>'off' OR operation_id IS NULL OR operation_id='00000000-0000-0000-0000-000000000000' OR scope_environment IS NULL OR scope_domain IS NULL OR source_digest IS NULL OR source_digest!~'^[0-9a-f]{64}$'
  OR source_domain IS NULL OR jsonb_typeof(source_domain)<>'object' OR octet_length(source_domain::text)>262144
  OR source_domain->>'environment_id' IS DISTINCT FROM scope_environment::text OR source_domain->>'id' IS DISTINCT FROM scope_domain::text
  OR inspection IS NULL OR inspection->'activationAuthorized' IS DISTINCT FROM 'false'::jsonb THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid inactive preparation';
 END IF;
 INSERT INTO aegaeon.organization_import_operations(id,environment_id,domain_id,source_sha256,source_enabled,session_actor,maintenance_actor,state,receipt)
 VALUES(operation_id,scope_environment,scope_domain,source_digest,(source_domain->>'enabled')::boolean,session_user,aegaeon.subject_history_maintenance_actor(),'writing',inspection);
 INSERT INTO aegaeon.authorization_domains(id,environment_id,name,is_default,enabled,revision,invitation_delivery,support_policy,support_policy_revision,import_operation_id)
 SELECT r.id,r.environment_id,r.name,r.is_default,false,r.revision,r.invitation_delivery,r.support_policy,r.support_policy_revision,operation_id FROM jsonb_populate_record(NULL::aegaeon.authorization_domains,source_domain) r;
END
$function$;
$definition$;
EXECUTE $definition$
CREATE FUNCTION aegaeon.organization_import_row_v1(operation_id uuid, section_name text, payload jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET timezone = 'UTC' SET datestyle = 'ISO, YMD'
AS $function$
DECLARE operation aegaeon.organization_import_operations%ROWTYPE;
BEGIN
 PERFORM aegaeon.subject_history_maintenance_actor();
 SELECT * INTO operation FROM aegaeon.organization_import_operations WHERE id=operation_id FOR UPDATE;
 IF NOT FOUND OR operation.state<>'writing' OR payload IS NULL OR jsonb_typeof(payload)<>'object' OR octet_length(payload::text)>262144 THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid inactive import row';
 END IF;
 IF section_name='outbox' THEN
  IF NOT EXISTS(SELECT FROM aegaeon.organization_authority_events WHERE id=(payload->>'event_id')::uuid AND environment_id=operation.environment_id AND domain_id=operation.domain_id) THEN
   RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='inactive outbox scope mismatch';
  END IF;
 ELSIF payload->>'environment_id' IS DISTINCT FROM operation.environment_id::text OR payload->>'domain_id' IS DISTINCT FROM operation.domain_id::text THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='inactive row scope mismatch';
 END IF;
 CASE section_name
 WHEN 'targets' THEN INSERT INTO aegaeon.authorization_domain_targets(environment_id,domain_id,audience,management,introspection_clients) SELECT r.environment_id,r.domain_id,r.audience,r.management,r.introspection_clients FROM jsonb_populate_record(NULL::aegaeon.authorization_domain_targets,payload) r;
 WHEN 'roles' THEN INSERT INTO aegaeon.organization_role_definitions(environment_id,domain_id,role_key,version,privileges,manages_members,assignable_roles) SELECT r.environment_id,r.domain_id,r.role_key,r.version,r.privileges,r.manages_members,r.assignable_roles FROM jsonb_populate_record(NULL::aegaeon.organization_role_definitions,payload) r;
 WHEN 'client_bindings' THEN INSERT INTO aegaeon.organization_client_bindings(id,environment_id,domain_id,client_registration_id,client_identifier,active,revision,targets,created_at) SELECT r.id,r.environment_id,r.domain_id,r.client_registration_id,r.client_identifier,r.active,r.revision,r.targets,r.created_at FROM jsonb_populate_record(NULL::aegaeon.organization_client_bindings,payload) r;
 WHEN 'operators' THEN INSERT INTO aegaeon.organization_operator_grants(id,environment_id,domain_id,administrator_id,active,revision,capabilities,created_at) SELECT r.id,r.environment_id,r.domain_id,r.administrator_id,r.active,r.revision,r.capabilities,r.created_at FROM jsonb_populate_record(NULL::aegaeon.organization_operator_grants,payload) r;
 WHEN 'organizations' THEN INSERT INTO aegaeon.application_organizations(id,environment_id,domain_id,external_id,state,revision,grant_generation,created_at) SELECT r.id,r.environment_id,r.domain_id,r.external_id,r.state,r.revision,r.grant_generation,r.created_at FROM jsonb_populate_record(NULL::aegaeon.application_organizations,payload) r;
 WHEN 'memberships' THEN INSERT INTO aegaeon.organization_memberships(environment_id,domain_id,organization_id,end_user_id,incarnation,state,revision,grant_generation,roles) SELECT r.environment_id,r.domain_id,r.organization_id,r.end_user_id,r.incarnation,r.state,r.revision,r.grant_generation,r.roles FROM jsonb_populate_record(NULL::aegaeon.organization_memberships,payload) r;
 WHEN 'invitations' THEN INSERT INTO aegaeon.organization_invitations(id,environment_id,domain_id,organization_id,revision,state,recipient,authority,issued_at,expires_at,delivery_revision,delivered_at,accepted_challenge_id,result,delivery_outcome,capability_hash) SELECT r.id,r.environment_id,r.domain_id,r.organization_id,r.revision,r.state,r.recipient,r.authority,r.issued_at,r.expires_at,r.delivery_revision,r.delivered_at,r.accepted_challenge_id,r.result,r.delivery_outcome,r.capability_hash FROM jsonb_populate_record(NULL::aegaeon.organization_invitations,payload||jsonb_build_object('capability_hash',CASE WHEN (payload->>'delivery_revision')::bigint=0 THEN NULL ELSE chr(92)||'x'||encode(sha256(convert_to(gen_random_uuid()::text||gen_random_uuid()::text,'UTF8')),'hex') END)) r;
 WHEN 'challenges' THEN INSERT INTO aegaeon.organization_invitation_challenges(id,environment_id,domain_id,invitation_id,invitation_delivery_revision,recipient_binding,request_key,issued_at,expires_at,delivery_revision,delivered_at,delivery_outcome,capability_hash) SELECT r.id,r.environment_id,r.domain_id,r.invitation_id,r.invitation_delivery_revision,r.recipient_binding,r.request_key,r.issued_at,r.expires_at,r.delivery_revision,r.delivered_at,r.delivery_outcome,r.capability_hash FROM jsonb_populate_record(NULL::aegaeon.organization_invitation_challenges,payload||jsonb_build_object('capability_hash',CASE WHEN (payload->>'delivery_revision')::bigint=0 THEN NULL ELSE chr(92)||'x'||encode(sha256(convert_to(gen_random_uuid()::text||gen_random_uuid()::text,'UTF8')),'hex') END)) r;
 WHEN 'identity_requests' THEN INSERT INTO aegaeon.organization_identity_requests(id,environment_id,domain_id,invitation_id,invitation_delivery_revision,policy_revision,purpose,request_key,request_digest,target_user_id,target_identity_revision,issued_at,expires_at,state,result,delivery_revision,delivered_at,delivery_outcome,capability_hash) SELECT r.id,r.environment_id,r.domain_id,r.invitation_id,r.invitation_delivery_revision,r.policy_revision,r.purpose,r.request_key,r.request_digest,r.target_user_id,r.target_identity_revision,r.issued_at,r.expires_at,r.state,r.result,r.delivery_revision,r.delivered_at,r.delivery_outcome,r.capability_hash FROM jsonb_populate_record(NULL::aegaeon.organization_identity_requests,payload||jsonb_build_object('request_digest',CASE WHEN payload->>'request_digest' IS NULL THEN NULL ELSE chr(92)||'x'||(payload->>'request_digest') END,'capability_hash',CASE WHEN (payload->>'delivery_revision')::bigint=0 THEN NULL ELSE chr(92)||'x'||encode(sha256(convert_to(gen_random_uuid()::text||gen_random_uuid()::text,'UTF8')),'hex') END)) r;
 WHEN 'administrative_grants' THEN INSERT INTO aegaeon.organization_admin_access_grants(id,environment_id,domain_id,organization_id,user_id,client_registration_id,root_id,authority,revision,active,issued_at,expires_at,creation_key,request_digest,revocation_key,revocation_digest) SELECT r.id,r.environment_id,r.domain_id,r.organization_id,r.user_id,r.client_registration_id,r.root_id,r.authority,r.revision,r.active,r.issued_at,r.expires_at,r.creation_key,r.request_digest,r.revocation_key,r.revocation_digest FROM jsonb_populate_record(NULL::aegaeon.organization_admin_access_grants,payload||jsonb_build_object('request_digest',CASE WHEN payload->>'request_digest' IS NULL THEN NULL ELSE chr(92)||'x'||(payload->>'request_digest') END,'revocation_digest',CASE WHEN payload->>'revocation_digest' IS NULL THEN NULL ELSE chr(92)||'x'||(payload->>'revocation_digest') END)) r;
 WHEN 'audit' THEN INSERT INTO aegaeon.organization_authority_events(id,environment_id,domain_id,organization_id,actor_id,actor_kind,client_id,client_registration_id,request_id,reason,event_type,data,created_at) SELECT r.id,r.environment_id,r.domain_id,r.organization_id,r.actor_id,r.actor_kind,r.client_id,r.client_registration_id,r.request_id,r.reason,r.event_type,r.data,r.created_at FROM jsonb_populate_record(NULL::aegaeon.organization_authority_events,payload) r;
 WHEN 'receipts' THEN INSERT INTO aegaeon.organization_authority_receipts(environment_id,domain_id,actor_id,actor_kind,client_id,client_registration_id,operation,idempotency_key,request_digest,result,created_at) SELECT r.environment_id,r.domain_id,r.actor_id,r.actor_kind,r.client_id,r.client_registration_id,r.operation,r.idempotency_key,r.request_digest,r.result,r.created_at FROM jsonb_populate_record(NULL::aegaeon.organization_authority_receipts,payload||jsonb_build_object('request_digest',CASE WHEN payload->>'request_digest' IS NULL THEN NULL ELSE chr(92)||'x'||(payload->>'request_digest') END)) r;
 WHEN 'outbox' THEN INSERT INTO aegaeon.organization_authority_outbox(event_id,attempts,delivered_at) SELECT r.event_id,r.attempts,r.delivered_at FROM jsonb_populate_record(NULL::aegaeon.organization_authority_outbox,payload) r;
 ELSE RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='unknown inactive import section';
 END CASE;
END
$function$;
$definition$;
EXECUTE $definition$
CREATE FUNCTION aegaeon.organization_import_finish_v1(operation_id uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE result jsonb;
BEGIN
 PERFORM aegaeon.subject_history_maintenance_actor();
 UPDATE aegaeon.organization_import_operations SET state='prepared'
 WHERE id=operation_id AND state='writing' RETURNING receipt INTO result;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='inactive import phase mismatch'; END IF;
 RETURN result;
END
$function$;
$definition$;
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.authorization_domains FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.authorization_domain_targets FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.organization_role_definitions FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.organization_client_bindings FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.organization_operator_grants FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.application_organizations FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.organization_memberships FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.organization_invitations FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.organization_invitation_challenges FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.organization_identity_requests FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.organization_admin_access_grants FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.organization_authority_events FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.organization_authority_receipts FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.organization_authority_outbox FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
REVOKE ALL ON FUNCTION aegaeon.organization_import_hold_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION aegaeon.organization_import_operation_v1(uuid,uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aegaeon.organization_import_operation_v1(uuid,uuid,uuid,text) TO aegaeon_subject_maintenance;
REVOKE ALL ON FUNCTION aegaeon.organization_import_begin_v1(uuid,uuid,uuid,text,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aegaeon.organization_import_begin_v1(uuid,uuid,uuid,text,jsonb,jsonb) TO aegaeon_subject_maintenance;
REVOKE ALL ON FUNCTION aegaeon.organization_import_row_v1(uuid,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aegaeon.organization_import_row_v1(uuid,text,jsonb) TO aegaeon_subject_maintenance;
REVOKE ALL ON FUNCTION aegaeon.organization_import_finish_v1(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aegaeon.organization_import_finish_v1(uuid) TO aegaeon_subject_maintenance;
RESET ROLE;
END
$installation$;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;
REVOKE REFERENCES ON aegaeon.environments FROM aegaeon_subject_owner;

-- END ORGANIZATIONS COMPONENT organization_inactive_import

-- BEGIN ORGANIZATIONS COMPONENT identity_creation_receipts
-- ORG-R02/R19/R21, ORG-G02/G13: immutable primary creation evidence.
-- Stop and drain all serving writers before this administrator migration.
DO $preflight$
BEGIN
 IF pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE') THEN
  RAISE EXCEPTION 'subject owner has preexisting schema CREATE';
 END IF;
END
$preflight$;
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
DO $installation$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
CREATE TABLE aegaeon.organization_creation_receipts (
 environment_id uuid NOT NULL,
 operation_id uuid NOT NULL CHECK(operation_id<>'00000000-0000-0000-0000-000000000000'),
 kind text COLLATE "C" NOT NULL CHECK(kind IN ('management_create','management_invite','management_csv','registration','upstream')),
 selector_sha256 text COLLATE "C" NOT NULL CHECK(octet_length(selector_sha256)=64 AND selector_sha256 ~ '^[0-9a-f]{64}$'),
 actor_sha256 text COLLATE "C" NOT NULL CHECK(octet_length(actor_sha256)=64 AND actor_sha256 ~ '^[0-9a-f]{64}$'),
 payload_sha256 text COLLATE "C" NOT NULL CHECK(octet_length(payload_sha256)=64 AND payload_sha256 ~ '^[0-9a-f]{64}$'),
 owner_id uuid NOT NULL UNIQUE CHECK(owner_id<>'00000000-0000-0000-0000-000000000000'),
 subject text COLLATE "C" NOT NULL CHECK(aegaeon.subject_ownership_valid_subject(subject)),
 attempt integer NOT NULL CHECK(attempt BETWEEN 1 AND 32),
 epoch uuid NOT NULL CHECK(epoch<>'00000000-0000-0000-0000-000000000000'),
 identity_revision bigint NOT NULL CHECK(identity_revision>0 AND identity_revision<9223372036854775807),
 receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32),
 recorded_at timestamptz NOT NULL DEFAULT statement_timestamp(),
 PRIMARY KEY(environment_id,operation_id),
 UNIQUE(environment_id,kind,selector_sha256),
 FOREIGN KEY(owner_id,environment_id) REFERENCES aegaeon.end_user_identity_owners(owner_id,environment_id)
);
REVOKE ALL ON aegaeon.organization_creation_receipts FROM PUBLIC;
CREATE TRIGGER organization_creation_owner_insert BEFORE INSERT ON aegaeon.organization_creation_receipts
FOR EACH ROW EXECUTE FUNCTION aegaeon.subject_ownership_guard_insert();
CREATE TRIGGER organization_creation_immutable BEFORE UPDATE OR DELETE ON aegaeon.organization_creation_receipts
FOR EACH ROW EXECUTE FUNCTION aegaeon.subject_ownership_immutable();
CREATE TRIGGER organization_creation_no_truncate BEFORE TRUNCATE ON aegaeon.organization_creation_receipts
FOR EACH STATEMENT EXECUTE FUNCTION aegaeon.subject_ownership_immutable();
EXECUTE $definition$
CREATE FUNCTION aegaeon.organization_creation_record_v1(input jsonb) RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE r aegaeon.organization_creation_receipts%ROWTYPE; previous aegaeon.organization_creation_receipts%ROWTYPE;
 field text; computed bytea;
BEGIN
 IF input IS NULL OR jsonb_typeof(input)<>'object' OR octet_length(input::text)>4096 THEN
  RAISE EXCEPTION 'creation receipt shape refused';
 END IF;
 IF (SELECT count(*) FROM jsonb_object_keys(input))<>11 OR input-ARRAY[
  'environment_id','operation_id','kind','selector_sha256','actor_sha256','payload_sha256','owner_id','subject','attempt','epoch','identity_revision']<>'{}'::jsonb THEN
  RAISE EXCEPTION 'creation receipt fields refused';
 END IF;
 FOREACH field IN ARRAY ARRAY['environment_id','operation_id','kind','selector_sha256','actor_sha256','payload_sha256','owner_id','subject','epoch'] LOOP
  IF jsonb_typeof(input->field) IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'creation receipt field type refused'; END IF;
 END LOOP;
 IF jsonb_typeof(input->'attempt') IS DISTINCT FROM 'number' OR jsonb_typeof(input->'identity_revision') IS DISTINCT FROM 'number' THEN
  RAISE EXCEPTION 'creation receipt counter type refused';
 END IF;
 SELECT * INTO r FROM jsonb_populate_record(NULL::aegaeon.organization_creation_receipts,input);
 IF NOT EXISTS(SELECT FROM aegaeon.end_users WHERE id=r.owner_id AND environment_id=r.environment_id
   AND subject=r.subject COLLATE "C" AND status<>'DELETED' AND organization_identity_revision=r.identity_revision FOR UPDATE) THEN
  RAISE EXCEPTION 'creation receipt current identity mismatch';
 END IF;
 computed:=sha256(convert_to('aegaeon-creation-primary-v1','UTF8')||decode('00','hex')||uuid_send(r.environment_id)||uuid_send(r.operation_id)
  ||int4send(octet_length(r.kind))||convert_to(r.kind,'UTF8')||decode(r.selector_sha256,'hex')||decode(r.actor_sha256,'hex')||decode(r.payload_sha256,'hex')
  ||uuid_send(r.owner_id)||int4send(octet_length(r.subject))||convert_to(r.subject,'UTF8')||int4send(r.attempt)||uuid_send(r.epoch)||int8send(r.identity_revision));
 SELECT * INTO previous FROM aegaeon.organization_creation_receipts WHERE environment_id=r.environment_id AND operation_id=r.operation_id;
 IF FOUND THEN
  IF (to_jsonb(previous)-ARRAY['receipt_sha256','recorded_at']) IS DISTINCT FROM input OR previous.receipt_sha256 IS DISTINCT FROM computed THEN
   RAISE EXCEPTION 'creation receipt replay conflict';
  END IF;
  RETURN computed;
 END IF;
 INSERT INTO aegaeon.organization_creation_receipts(environment_id,operation_id,kind,selector_sha256,actor_sha256,payload_sha256,owner_id,subject,attempt,epoch,identity_revision,receipt_sha256)
 VALUES(r.environment_id,r.operation_id,r.kind,r.selector_sha256,r.actor_sha256,r.payload_sha256,r.owner_id,r.subject,r.attempt,r.epoch,r.identity_revision,computed);
 RETURN computed;
END
$function$;
$definition$;
REVOKE ALL ON FUNCTION aegaeon.organization_creation_record_v1(jsonb) FROM PUBLIC;
RESET ROLE;
END
$installation$;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;

-- END ORGANIZATIONS COMPONENT identity_creation_receipts

-- BEGIN ORGANIZATIONS COMPONENT subject_history_restoration
-- Permanent facts only: no identity, credential, grant or activation writes.
-- Stop and drain serving writers before this separately authorized migration.
DO $preflight$
BEGIN
 IF pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE') THEN
  RAISE EXCEPTION 'subject owner has preexisting schema CREATE';
 END IF;
END
$preflight$;
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
DO $installation$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
CREATE TABLE aegaeon.subject_history_restorations (
 operation_id uuid PRIMARY KEY CHECK(operation_id<>'00000000-0000-0000-0000-000000000000'),
 environment_id uuid NOT NULL REFERENCES aegaeon.subject_ownership_namespaces(environment_id),
 source jsonb NOT NULL CHECK(jsonb_typeof(source)='object' AND octet_length(source::text)<=4096),
 recorded_at timestamptz NOT NULL DEFAULT statement_timestamp(),
 session_actor text NOT NULL
);
CREATE TABLE aegaeon.subject_history_restoration_pages (
 operation_id uuid NOT NULL REFERENCES aegaeon.subject_history_restorations(operation_id),
 after_sequence bigint NOT NULL CHECK(after_sequence BETWEEN 0 AND 999999),
 entry_count integer NOT NULL CHECK(entry_count BETWEEN 1 AND 256),
 digest bytea NOT NULL CHECK(octet_length(digest)=32),
 input jsonb NOT NULL CHECK(jsonb_typeof(input)='object' AND octet_length(input::text)<=1048576),
 recorded_at timestamptz NOT NULL DEFAULT statement_timestamp(),
 session_actor text NOT NULL,
 PRIMARY KEY(operation_id,after_sequence),
 CHECK(after_sequence+entry_count<=1000000)
);
CREATE INDEX subject_history_restorations_environment ON aegaeon.subject_history_restorations(environment_id);
REVOKE ALL ON aegaeon.subject_history_restorations,aegaeon.subject_history_restoration_pages FROM PUBLIC;
CREATE TRIGGER subject_history_restorations_owner_insert BEFORE INSERT ON aegaeon.subject_history_restorations
FOR EACH ROW EXECUTE FUNCTION aegaeon.subject_ownership_guard_insert();
CREATE TRIGGER subject_history_restorations_immutable BEFORE UPDATE OR DELETE ON aegaeon.subject_history_restorations
FOR EACH ROW EXECUTE FUNCTION aegaeon.subject_ownership_immutable();
CREATE TRIGGER subject_history_restorations_no_truncate BEFORE TRUNCATE ON aegaeon.subject_history_restorations
FOR EACH STATEMENT EXECUTE FUNCTION aegaeon.subject_ownership_immutable();
CREATE TRIGGER subject_history_restoration_pages_owner_insert BEFORE INSERT ON aegaeon.subject_history_restoration_pages
FOR EACH ROW EXECUTE FUNCTION aegaeon.subject_ownership_guard_insert();
CREATE TRIGGER subject_history_restoration_pages_immutable BEFORE UPDATE OR DELETE ON aegaeon.subject_history_restoration_pages
FOR EACH ROW EXECUTE FUNCTION aegaeon.subject_ownership_immutable();
CREATE TRIGGER subject_history_restoration_pages_no_truncate BEFORE TRUNCATE ON aegaeon.subject_history_restoration_pages
FOR EACH STATEMENT EXECUTE FUNCTION aegaeon.subject_ownership_immutable();
EXECUTE $definition$
CREATE FUNCTION aegaeon.restore_subject_history_page_v1(input jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE operation uuid; environment uuid; deployment uuid; witness_operation uuid;
 revision bigint; issuer text; source_sequence bigint; source_digest bytea; page_after bigint;
 count_entries integer; source jsonb; previous_source jsonb; prior aegaeon.subject_history_restoration_pages%ROWTYPE;
 entry jsonb; owner uuid; reserved_subject text; recorded timestamptz; sequence bigint; digest bytea; previous bytea;
 actual_environment uuid; actual_owner uuid; field text;
BEGIN
 IF input IS NULL OR jsonb_typeof(input)<>'object' OR octet_length(input::text)>1048576
  OR (SELECT count(*) FROM jsonb_object_keys(input))<>11
  OR input-ARRAY['operation_id','environment_id','deployment_id','witness_operation_id','witness_revision',
   'issuer_host','source_sequence','source_digest','after_sequence','previous_digest','entries']<>'{}'::jsonb
 THEN RAISE EXCEPTION 'history restoration input shape'; END IF;
 IF jsonb_typeof(input->'entries') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'history restoration page shape'; END IF;
 FOREACH field IN ARRAY ARRAY['operation_id','environment_id','deployment_id','witness_operation_id','issuer_host','source_digest','previous_digest'] LOOP
  IF jsonb_typeof(input->field) IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'history restoration metadata type'; END IF;
 END LOOP;
 FOREACH field IN ARRAY ARRAY['witness_revision','source_sequence','after_sequence'] LOOP
  IF jsonb_typeof(input->field) IS DISTINCT FROM 'number' THEN RAISE EXCEPTION 'history restoration counter type'; END IF;
 END LOOP;
 operation:=(input->>'operation_id')::uuid; environment:=(input->>'environment_id')::uuid;
 deployment:=(input->>'deployment_id')::uuid; witness_operation:=(input->>'witness_operation_id')::uuid;
 revision:=(input->>'witness_revision')::bigint; issuer:=input->>'issuer_host';
 source_sequence:=(input->>'source_sequence')::bigint; page_after:=(input->>'after_sequence')::bigint;
 count_entries:=jsonb_array_length(input->'entries');
 IF operation IS NULL OR operation='00000000-0000-0000-0000-000000000000'
  OR environment IS NULL OR deployment IS NULL OR deployment='00000000-0000-0000-0000-000000000000'
  OR witness_operation IS NULL OR witness_operation='00000000-0000-0000-0000-000000000000'
  OR revision IS NULL OR revision<1 OR issuer IS NULL OR octet_length(issuer) NOT BETWEEN 1 AND 1024
  OR source_sequence IS NULL OR source_sequence NOT BETWEEN 1 AND 1000000
  OR page_after IS NULL OR page_after<0 OR page_after+count_entries>source_sequence
  OR count_entries NOT BETWEEN 1 AND 256
  OR page_after%256<>0 OR count_entries<>LEAST(256,source_sequence-page_after)
  OR input->>'source_digest' IS NULL OR input->>'source_digest' !~ '^[0-9a-f]{64}$'
  OR input->>'previous_digest' IS NULL OR input->>'previous_digest' !~ '^[0-9a-f]{64}$'
 THEN RAISE EXCEPTION 'history restoration metadata'; END IF;
 source_digest:=decode(input->>'source_digest','hex'); previous:=decode(input->>'previous_digest','hex');
 IF NOT EXISTS(SELECT FROM aegaeon.subject_ownership_namespaces n JOIN aegaeon.subject_ownership_adoptions a USING(environment_id)
  WHERE n.environment_id=environment AND n.issuer_host=issuer COLLATE "C")
 THEN RAISE EXCEPTION 'history restoration adopted namespace mismatch'; END IF;
 -- One durable namespace row serializes quota decisions across distinct IDs.
 -- Exact earlier operations remain usable after capacity is exhausted.
 PERFORM 1 FROM aegaeon.subject_ownership_namespaces n WHERE n.environment_id=environment FOR UPDATE;
 IF NOT EXISTS(SELECT FROM aegaeon.subject_history_restorations r WHERE r.operation_id=operation)
  AND (SELECT count(*) FROM aegaeon.subject_history_restorations r WHERE r.environment_id=environment)>=16
 THEN RAISE EXCEPTION 'history restoration operation capacity exhausted'; END IF;
 source:=input-ARRAY['after_sequence','previous_digest','entries'];
 INSERT INTO aegaeon.subject_history_restorations(operation_id,environment_id,source,session_actor)
 VALUES(operation,environment,source,session_user) ON CONFLICT(operation_id) DO NOTHING;
 SELECT r.source INTO STRICT previous_source FROM aegaeon.subject_history_restorations r WHERE r.operation_id=operation;
 IF previous_source IS DISTINCT FROM source THEN RAISE EXCEPTION 'history restoration operation conflict'; END IF;
 -- Serialize pages and exact concurrent replays using the immutable header row.
 PERFORM 1 FROM aegaeon.subject_history_restorations r WHERE r.operation_id=operation FOR UPDATE;
 SELECT * INTO prior FROM aegaeon.subject_history_restoration_pages p WHERE p.operation_id=operation AND p.after_sequence=page_after;
 IF FOUND THEN
  IF prior.input IS DISTINCT FROM input THEN RAISE EXCEPTION 'history restoration page conflict'; END IF;
  RETURN jsonb_build_object('operation_id',operation,'sequence',page_after+prior.entry_count,
   'digest',encode(prior.digest,'hex'),'complete',page_after+prior.entry_count=source_sequence,'activation_authorized',false);
 END IF;
 IF page_after=0 THEN
  digest:=sha256(convert_to('aegaeon-permanent-history-v1','UTF8')||decode('00','hex')||uuid_send(environment)
   ||int4send(octet_length(issuer))||convert_to(issuer,'UTF8'));
 ELSE
  SELECT * INTO prior FROM aegaeon.subject_history_restoration_pages p WHERE p.operation_id=operation
   ORDER BY p.after_sequence DESC LIMIT 1;
  IF NOT FOUND OR prior.after_sequence+prior.entry_count<>page_after THEN RAISE EXCEPTION 'history restoration prefix missing'; END IF;
  digest:=prior.digest;
 END IF;
 IF digest IS DISTINCT FROM previous THEN RAISE EXCEPTION 'history restoration page link'; END IF;
 sequence:=page_after;
 FOR entry IN SELECT value FROM jsonb_array_elements(input->'entries') LOOP
  sequence:=sequence+1;
  IF jsonb_typeof(entry)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(entry))<>13
   OR entry-ARRAY['sequence','kind','owner_id','subject','operation_id','epoch','worker_id','slot','generation','principal','recorded_at','previous_digest','digest']<>'{}'::jsonb
   OR jsonb_typeof(entry->'sequence') IS DISTINCT FROM 'number'
   OR jsonb_typeof(entry->'kind') IS DISTINCT FROM 'string'
   OR jsonb_typeof(entry->'principal') IS DISTINCT FROM 'string'
   OR octet_length(entry->>'principal') NOT BETWEEN 1 AND 63
   OR jsonb_typeof(entry->'operation_id') IS DISTINCT FROM 'string'
   OR (entry->>'operation_id')::uuid='00000000-0000-0000-0000-000000000000'
   OR (entry->>'sequence')::bigint IS DISTINCT FROM sequence
   OR entry->>'previous_digest' IS DISTINCT FROM encode(digest,'hex')
   OR entry->>'digest' IS NULL OR entry->>'digest' !~ '^[0-9a-f]{64}$'
   OR jsonb_typeof(entry->'owner_id') IS DISTINCT FROM 'string'
   OR jsonb_typeof(entry->'recorded_at') IS DISTINCT FROM 'string'
  THEN RAISE EXCEPTION 'history restoration entry shape'; END IF;
  IF (entry->'epoch'='null'::jsonb AND entry->'worker_id'='null'::jsonb
      AND entry->'slot'='null'::jsonb AND entry->'generation'='null'::jsonb) THEN NULL;
  ELSIF jsonb_typeof(entry->'epoch')='string' AND jsonb_typeof(entry->'worker_id')='string'
      AND jsonb_typeof(entry->'slot')='number' AND jsonb_typeof(entry->'generation')='number'
      AND (entry->>'epoch')::uuid<>'00000000-0000-0000-0000-000000000000'
      AND (entry->>'worker_id')::uuid<>'00000000-0000-0000-0000-000000000000'
      AND (entry->>'slot')::integer BETWEEN 0 AND 63 AND (entry->>'generation')::bigint>0 THEN NULL;
  ELSE RAISE EXCEPTION 'history restoration provenance shape'; END IF;
  owner:=(entry->>'owner_id')::uuid; recorded:=(entry->>'recorded_at')::timestamptz;
  IF NOT isfinite(recorded) THEN RAISE EXCEPTION 'history restoration timestamp'; END IF;
  reserved_subject:=entry->>'subject';
  IF entry->>'kind'='owner' AND entry->'subject'='null'::jsonb THEN
   digest:=sha256(digest||int8send(sequence)||decode('00','hex')||uuid_send(owner)||int4send(0));
   INSERT INTO aegaeon.end_user_identity_owners(owner_id,environment_id,recorded_at)
    VALUES(owner,environment,recorded) ON CONFLICT(owner_id) DO NOTHING;
   SELECT o.environment_id INTO STRICT actual_environment FROM aegaeon.end_user_identity_owners o WHERE o.owner_id=owner;
   IF actual_environment IS DISTINCT FROM environment THEN RAISE EXCEPTION 'history restoration owner conflict'; END IF;
  ELSIF entry->>'kind'='reservation' AND jsonb_typeof(entry->'subject')='string'
   AND aegaeon.subject_ownership_valid_subject(reserved_subject) THEN
   digest:=sha256(digest||int8send(sequence)||decode('01','hex')||uuid_send(owner)||int4send(octet_length(reserved_subject))||convert_to(reserved_subject,'UTF8'));
   INSERT INTO aegaeon.end_user_subject_reservations(environment_id,subject,owner_id,recorded_at)
    VALUES(environment,reserved_subject,owner,recorded) ON CONFLICT ON CONSTRAINT end_user_subject_reservations_pkey DO NOTHING;
   SELECT s.owner_id INTO STRICT actual_owner FROM aegaeon.end_user_subject_reservations s
    WHERE s.environment_id=environment AND s.subject=reserved_subject COLLATE "C";
   IF actual_owner IS DISTINCT FROM owner THEN RAISE EXCEPTION 'history restoration subject conflict'; END IF;
  ELSE RAISE EXCEPTION 'history restoration entry kind'; END IF;
  IF encode(digest,'hex') IS DISTINCT FROM entry->>'digest' THEN RAISE EXCEPTION 'history restoration entry digest'; END IF;
 END LOOP;
 IF sequence=source_sequence AND digest IS DISTINCT FROM source_digest THEN RAISE EXCEPTION 'history restoration source head'; END IF;
 INSERT INTO aegaeon.subject_history_restoration_pages(operation_id,after_sequence,entry_count,digest,input,session_actor)
 VALUES(operation,page_after,count_entries,digest,input,session_user);
 RETURN jsonb_build_object('operation_id',operation,'sequence',sequence,'digest',encode(digest,'hex'),
  'complete',sequence=source_sequence,'activation_authorized',false);
END
$function$;
$definition$;
REVOKE ALL ON FUNCTION aegaeon.restore_subject_history_page_v1(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aegaeon.restore_subject_history_page_v1(jsonb) TO aegaeon_subject_maintenance;
RESET ROLE;
END
$installation$;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;

-- END ORGANIZATIONS COMPONENT subject_history_restoration


-- BEGIN ORGANIZATIONS COMPONENT organization_prepared_inspection
-- ORG-R18/R19: bounded current prepared-content inspection; no activation.
DO $preflight$
BEGIN
 IF pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE') THEN RAISE EXCEPTION 'subject owner has preexisting schema CREATE'; END IF;
END
$preflight$;
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
DO $installation$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
EXECUTE $definition$
CREATE FUNCTION aegaeon.organization_import_prepared_rows_v1(
 operation_id uuid, scope_environment uuid, scope_domain uuid, source_digest text,
 section_name text, after_key text, page_limit integer
) RETURNS TABLE(row_key text,row_data text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET timezone = 'UTC' SET datestyle = 'ISO, YMD'
AS $function$
DECLARE statement text; receipt jsonb;
BEGIN
 PERFORM aegaeon.subject_history_maintenance_actor();
 IF operation_id IS NULL OR scope_environment IS NULL OR scope_domain IS NULL OR source_digest IS NULL
  OR section_name IS NULL OR page_limit IS NULL OR page_limit NOT BETWEEN 1 AND 10 OR octet_length(after_key)>4096 THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid prepared content inspection';
 END IF;
 receipt:=aegaeon.organization_import_operation_v1(operation_id,scope_environment,scope_domain,source_digest);
 IF receipt IS NULL OR NOT EXISTS(SELECT FROM aegaeon.authorization_domains d
   WHERE d.environment_id=scope_environment AND d.id=scope_domain AND d.import_operation_id=operation_id AND NOT d.enabled) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='prepared inactive scope missing';
 END IF;
 CASE section_name
 WHEN 'domain' THEN statement := 'SELECT (id)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT id,environment_id,name,is_default,enabled,revision,invitation_delivery,support_policy,support_policy_revision FROM aegaeon.authorization_domains WHERE environment_id=$1 AND id=$2) v';
 WHEN 'targets' THEN statement := 'SELECT (audience)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT environment_id,domain_id,audience,management,introspection_clients FROM aegaeon.authorization_domain_targets WHERE environment_id=$1 AND domain_id=$2) v';
 WHEN 'roles' THEN statement := 'SELECT (role_key)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT environment_id,domain_id,role_key,version,privileges,manages_members,assignable_roles FROM aegaeon.organization_role_definitions WHERE environment_id=$1 AND domain_id=$2) v';
 WHEN 'client_bindings' THEN statement := 'SELECT (id)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT id,environment_id,domain_id,client_registration_id,client_identifier,active,revision,targets,created_at FROM aegaeon.organization_client_bindings WHERE environment_id=$1 AND domain_id=$2) v';
 WHEN 'operators' THEN statement := 'SELECT (id)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT id,environment_id,domain_id,administrator_id,active,revision,capabilities,created_at FROM aegaeon.organization_operator_grants WHERE environment_id=$1 AND domain_id=$2) v';
 WHEN 'organizations' THEN statement := 'SELECT (id)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT id,environment_id,domain_id,external_id,state,revision,grant_generation,created_at FROM aegaeon.application_organizations WHERE environment_id=$1 AND domain_id=$2) v';
 WHEN 'memberships' THEN statement := 'SELECT (jsonb_build_array(organization_id,end_user_id)::text)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT environment_id,domain_id,organization_id,end_user_id,incarnation,state,revision,grant_generation,roles FROM aegaeon.organization_memberships WHERE environment_id=$1 AND domain_id=$2) v';
 WHEN 'invitations' THEN statement := 'SELECT (id)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT id,environment_id,domain_id,organization_id,revision,state,recipient,authority,issued_at,expires_at,delivery_revision,delivered_at,accepted_challenge_id,result,delivery_outcome FROM aegaeon.organization_invitations WHERE environment_id=$1 AND domain_id=$2) v';
 WHEN 'challenges' THEN statement := 'SELECT (id)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT id,environment_id,domain_id,invitation_id,invitation_delivery_revision,recipient_binding,request_key,issued_at,expires_at,delivery_revision,delivered_at,delivery_outcome FROM aegaeon.organization_invitation_challenges WHERE environment_id=$1 AND domain_id=$2) v';
 WHEN 'identity_requests' THEN statement := 'SELECT (id)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT id,environment_id,domain_id,invitation_id,invitation_delivery_revision,policy_revision,purpose,request_key,encode(request_digest,''hex'') AS request_digest,target_user_id,target_identity_revision,issued_at,expires_at,state,result,delivery_revision,delivered_at,delivery_outcome FROM aegaeon.organization_identity_requests WHERE environment_id=$1 AND domain_id=$2) v';
 WHEN 'administrative_grants' THEN statement := 'SELECT (id)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT id,environment_id,domain_id,organization_id,user_id,client_registration_id,root_id,authority,revision,active,issued_at,expires_at,creation_key,encode(request_digest,''hex'') AS request_digest,revocation_key,encode(revocation_digest,''hex'') AS revocation_digest FROM aegaeon.organization_admin_access_grants WHERE environment_id=$1 AND domain_id=$2) v';
 WHEN 'audit' THEN statement := 'SELECT (id)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT id,environment_id,domain_id,organization_id,actor_id,actor_kind,client_id,client_registration_id,request_id,reason,event_type,data,created_at FROM aegaeon.organization_authority_events WHERE environment_id=$1 AND domain_id=$2) v';
 WHEN 'receipts' THEN statement := 'SELECT (jsonb_build_array(actor_id,actor_kind,client_id,client_registration_id,operation,idempotency_key)::text)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT environment_id,domain_id,actor_id,actor_kind,client_id,client_registration_id,operation,idempotency_key,encode(request_digest,''hex'') AS request_digest,result,created_at FROM aegaeon.organization_authority_receipts WHERE environment_id=$1 AND domain_id=$2) v';
 WHEN 'outbox' THEN statement := 'SELECT (event_id)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT event_id,attempts,delivered_at FROM aegaeon.organization_authority_outbox WHERE EXISTS(SELECT 1 FROM aegaeon.organization_authority_events e WHERE e.id=event_id AND e.environment_id=$1 AND e.domain_id=$2)) v';
 ELSE RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='unknown prepared section';
 END CASE;
 RETURN QUERY EXECUTE 'SELECT r.row_key,CASE WHEN octet_length(r.row_data)<=262144 THEN r.row_data ELSE NULL END FROM ('||statement||') r WHERE $3::text IS NULL OR r.row_key COLLATE "C">$3 COLLATE "C" ORDER BY r.row_key COLLATE "C" LIMIT $4'
 USING scope_environment,scope_domain,after_key,page_limit;
END
$function$;
$definition$;
REVOKE ALL ON FUNCTION aegaeon.organization_import_prepared_rows_v1(uuid,uuid,uuid,text,text,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aegaeon.organization_import_prepared_rows_v1(uuid,uuid,uuid,text,text,text,integer) TO aegaeon_subject_maintenance;

RESET ROLE;
END
$installation$;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;

-- END ORGANIZATIONS COMPONENT organization_prepared_inspection


-- BEGIN ORGANIZATIONS COMPONENT runtime_security_budgets
-- Security decisions belong to the selected application database, not a cache.
-- An authorized PITR restores these budgets together with the rest of that DB.
CREATE TABLE aegaeon.runtime_security_budgets (
    namespace text COLLATE "C" NOT NULL CHECK (octet_length(namespace) BETWEEN 1 AND 256),
    bucket bytea NOT NULL CHECK (octet_length(bucket) = 32),
    attempts bigint NOT NULL CHECK (attempts BETWEEN 0 AND 4294967295),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (namespace, bucket)
);
CREATE INDEX runtime_security_budgets_expiry_idx
    ON aegaeon.runtime_security_budgets (namespace, expires_at);

-- Invoker rights: the runtime role needs SELECT/INSERT/UPDATE/DELETE on the table.
-- Sorted row locks make the multi-bucket decision atomic without a global lock.
CREATE FUNCTION aegaeon.consume_runtime_security_budget(
    p_namespace text, p_buckets bytea[], p_limit bigint, p_window_ms bigint
) RETURNS boolean
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
DECLARE
    item bytea;
    ordered bytea[];
    current_attempts bigint;
    current_expiry timestamptz;
    observed_at timestamptz;
BEGIN
    IF p_namespace IS NULL OR octet_length(p_namespace) NOT BETWEEN 1 AND 256
       OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 4294967295
       OR p_window_ms IS NULL OR p_window_ms NOT BETWEEN 1 AND 86400000
       OR p_buckets IS NULL OR cardinality(p_buckets) NOT BETWEEN 1 AND 16
       OR array_ndims(p_buckets) <> 1
       OR EXISTS (SELECT FROM unnest(p_buckets) b WHERE b IS NULL OR octet_length(b) <> 32)
    THEN
        RAISE EXCEPTION 'invalid security budget input' USING ERRCODE = '22023';
    END IF;
    SELECT array_agg(b ORDER BY b) INTO ordered FROM (SELECT DISTINCT unnest(p_buckets) b) unique_buckets;
    observed_at := clock_timestamp();
    FOREACH item IN ARRAY ordered LOOP
        INSERT INTO aegaeon.runtime_security_budgets(namespace, bucket, attempts, expires_at)
        VALUES (p_namespace, item, 0, observed_at + p_window_ms * interval '1 millisecond')
        ON CONFLICT (namespace, bucket) DO NOTHING;
        -- Lock even an exhausted bucket. The decision is one transaction.
        PERFORM 1 FROM aegaeon.runtime_security_budgets
        WHERE namespace = p_namespace AND bucket = item FOR UPDATE;
    END LOOP;
    observed_at := clock_timestamp();
    FOREACH item IN ARRAY ordered LOOP
        SELECT attempts, expires_at INTO STRICT current_attempts, current_expiry
        FROM aegaeon.runtime_security_budgets WHERE namespace = p_namespace AND bucket = item;
        IF current_expiry > observed_at AND current_attempts >= p_limit THEN
            RETURN false;
        END IF;
    END LOOP;
    UPDATE aegaeon.runtime_security_budgets
    SET attempts = CASE WHEN expires_at <= observed_at THEN 1 ELSE attempts + 1 END,
        expires_at = CASE WHEN expires_at <= observed_at
            THEN observed_at + p_window_ms * interval '1 millisecond' ELSE expires_at END
    WHERE namespace = p_namespace AND bucket = ANY(ordered);
    RETURN true;
END
$function$;

-- END ORGANIZATIONS COMPONENT runtime_security_budgets

-- BEGIN ORGANIZATIONS COMPONENT runtime_replay
-- Expiring security decisions, not an event log or a restore journal.
CREATE TABLE aegaeon.runtime_replay_entries (
    namespace text COLLATE "C" NOT NULL CHECK (octet_length(namespace) BETWEEN 1 AND 256),
    token_digest text COLLATE "C" NOT NULL CHECK (token_digest ~ '^[A-Za-z0-9_-]{43}$'),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (namespace, token_digest)
);
CREATE INDEX runtime_replay_entries_expiry_idx
    ON aegaeon.runtime_replay_entries (namespace, expires_at);

CREATE FUNCTION aegaeon.record_runtime_replay(p_namespace text, p_digest text, p_ttl_ms bigint)
RETURNS boolean LANGUAGE plpgsql SET search_path = pg_catalog AS $function$
DECLARE
    recorded boolean;
BEGIN
    IF p_namespace IS NULL OR octet_length(p_namespace) NOT BETWEEN 1 AND 256
       OR p_digest IS NULL OR p_digest !~ '^[A-Za-z0-9_-]{43}$'
       OR p_ttl_ms IS NULL OR p_ttl_ms < 1 THEN
        RAISE EXCEPTION 'invalid replay input' USING ERRCODE = '22023';
    END IF;
    INSERT INTO aegaeon.runtime_replay_entries(namespace, token_digest, expires_at)
    VALUES (p_namespace, p_digest, clock_timestamp() + p_ttl_ms * interval '1 millisecond')
    ON CONFLICT (namespace, token_digest) DO UPDATE
    SET expires_at = clock_timestamp() + p_ttl_ms * interval '1 millisecond'
    WHERE runtime_replay_entries.expires_at <= clock_timestamp()
    RETURNING true INTO recorded;
    RETURN coalesce(recorded, false);
END
$function$;

-- END ORGANIZATIONS COMPONENT runtime_replay

-- BEGIN ORGANIZATIONS COMPONENT runtime_dpop_nonces
-- Bounded current/previous challenge values. Validation never rotates or extends them.
CREATE TABLE aegaeon.runtime_dpop_nonces (
    namespace text COLLATE "C" NOT NULL CHECK (octet_length(namespace) BETWEEN 1 AND 256),
    role text COLLATE "C" NOT NULL CHECK (role IN ('as','rs')),
    current_value text COLLATE "C" NOT NULL CHECK (current_value ~ '^[A-Za-z0-9_-]{43}$'),
    previous_value text COLLATE "C" CHECK (previous_value ~ '^[A-Za-z0-9_-]{43}$'),
    previous_until timestamptz,
    rotate_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (namespace, role),
    CHECK ((previous_value IS NULL) = (previous_until IS NULL)),
    CHECK (rotate_at < expires_at)
);
CREATE INDEX runtime_dpop_nonces_expiry_idx ON aegaeon.runtime_dpop_nonces(namespace,expires_at);

CREATE FUNCTION aegaeon.issue_runtime_dpop_nonce(p_namespace text,p_role text,p_fresh text,p_ttl_ms bigint)
RETURNS text LANGUAGE plpgsql SET search_path = pg_catalog AS $function$
DECLARE
    current_row aegaeon.runtime_dpop_nonces%ROWTYPE;
    observed_at timestamptz;
BEGIN
    IF p_namespace IS NULL OR octet_length(p_namespace) NOT BETWEEN 1 AND 256
       OR p_role IS NULL OR p_role NOT IN ('as','rs')
       OR p_fresh IS NULL OR p_fresh !~ '^[A-Za-z0-9_-]{43}$'
       OR p_ttl_ms IS NULL OR p_ttl_ms NOT BETWEEN 1 AND 86400000 THEN
        RAISE EXCEPTION 'invalid nonce input' USING ERRCODE='22023';
    END IF;
    observed_at := clock_timestamp();
    -- Establish and lock this one role row, including concurrent first issuance.
    INSERT INTO aegaeon.runtime_dpop_nonces(namespace,role,current_value,rotate_at,expires_at)
    VALUES(p_namespace,p_role,p_fresh,observed_at+p_ttl_ms*interval '1 millisecond',observed_at+p_ttl_ms*interval '2 milliseconds')
    ON CONFLICT(namespace,role) DO UPDATE SET current_value=runtime_dpop_nonces.current_value
    RETURNING * INTO current_row;
    observed_at := clock_timestamp();
    IF observed_at < current_row.rotate_at THEN
        RETURN current_row.current_value;
    END IF;
    UPDATE aegaeon.runtime_dpop_nonces
    SET current_value=p_fresh,
        previous_value=CASE WHEN current_row.expires_at>observed_at THEN current_row.current_value END,
        previous_until=CASE WHEN current_row.expires_at>observed_at THEN current_row.expires_at END,
        rotate_at=observed_at+p_ttl_ms*interval '1 millisecond',
        expires_at=observed_at+p_ttl_ms*interval '2 milliseconds'
    WHERE namespace=p_namespace AND role=p_role;
    RETURN p_fresh;
END
$function$;

-- END ORGANIZATIONS COMPONENT runtime_dpop_nonces

-- BEGIN ORGANIZATIONS COMPONENT runtime_csrf_tokens
-- Current, expiring one-use form capabilities. No raw token or event history.
CREATE TABLE aegaeon.runtime_csrf_tokens (
    namespace text COLLATE "C" NOT NULL CHECK (octet_length(namespace) BETWEEN 1 AND 256),
    token_digest bytea NOT NULL CHECK (octet_length(token_digest)=32),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY(namespace,token_digest)
);
CREATE INDEX runtime_csrf_tokens_expiry_idx ON aegaeon.runtime_csrf_tokens(namespace,expires_at);

-- END ORGANIZATIONS COMPONENT runtime_csrf_tokens

-- BEGIN ORGANIZATIONS COMPONENT runtime_logout_relays
-- One-use upstream logout callback routing, scoped to the selected Environment.
CREATE TABLE aegaeon.runtime_logout_relays (
    namespace text COLLATE "C" NOT NULL CHECK(octet_length(namespace) BETWEEN 1 AND 256),
    token_digest bytea NOT NULL CHECK(octet_length(token_digest)=32),
    incident_id uuid,
    downstream_redirect_uri text NOT NULL,
    downstream_state text,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY(namespace,token_digest)
);
CREATE INDEX runtime_logout_relays_expiry_idx ON aegaeon.runtime_logout_relays(namespace,expires_at);

-- END ORGANIZATIONS COMPONENT runtime_logout_relays

-- BEGIN ORGANIZATIONS COMPONENT runtime_upstream_auth
-- Current browser-bound upstream authorization continuations. The snapshot omits client secrets.
CREATE TABLE aegaeon.runtime_upstream_auth (
    namespace text COLLATE "C" NOT NULL CHECK(octet_length(namespace) BETWEEN 1 AND 256),
    token_digest bytea NOT NULL CHECK(octet_length(token_digest)=32),
    payload text COLLATE "C" NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY(namespace,token_digest)
);
CREATE INDEX runtime_upstream_auth_expiry_idx ON aegaeon.runtime_upstream_auth(namespace,expires_at);

-- END ORGANIZATIONS COMPONENT runtime_upstream_auth

-- BEGIN ORGANIZATIONS COMPONENT runtime_stepup
-- Current step-up challenges; bindings are a framed digest, not bearer session identifiers.
CREATE TABLE aegaeon.runtime_stepup_challenges (
    namespace text COLLATE "C" NOT NULL CHECK(octet_length(namespace) BETWEEN 1 AND 256),
    request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    challenge_id uuid NOT NULL,
    issued_at_epoch_secs bigint NOT NULL CHECK(issued_at_epoch_secs>=0),
    expires_at_epoch_secs bigint NOT NULL CHECK(expires_at_epoch_secs>issued_at_epoch_secs),
    expires_at timestamptz NOT NULL,
    completed boolean NOT NULL DEFAULT false,
    PRIMARY KEY(namespace,request_digest)
);
CREATE INDEX runtime_stepup_expiry_idx ON aegaeon.runtime_stepup_challenges(namespace,expires_at);

-- END ORGANIZATIONS COMPONENT runtime_stepup

-- BEGIN ORGANIZATIONS COMPONENT runtime_management_sessions
-- Only session creation serializes on its namespace; ordinary authentication reads do not.
CREATE TABLE aegaeon.runtime_management_session_scopes (
    namespace text COLLATE "C" PRIMARY KEY CHECK(octet_length(namespace) BETWEEN 1 AND 256)
);
CREATE TABLE aegaeon.runtime_management_sessions (
    namespace text COLLATE "C" NOT NULL REFERENCES aegaeon.runtime_management_session_scopes(namespace),
    token_digest bytea NOT NULL CHECK(octet_length(token_digest)=32),
    administrator_id uuid NOT NULL,
    created_at_epoch_secs bigint NOT NULL CHECK(created_at_epoch_secs>=0),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY(namespace,token_digest)
);
CREATE INDEX runtime_management_session_expiry_idx ON aegaeon.runtime_management_sessions(namespace,expires_at);
CREATE INDEX runtime_management_session_age_idx ON aegaeon.runtime_management_sessions(namespace,created_at_epoch_secs,token_digest);

CREATE FUNCTION aegaeon.create_runtime_management_session(
    p_namespace text,p_digest bytea,p_administrator uuid,p_created bigint,p_expiry timestamptz,p_capacity integer
) RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE retained bigint;
BEGIN
    IF p_capacity IS NULL OR p_capacity NOT BETWEEN 1 AND 1000000 OR p_created IS NULL OR p_created<0
       OR p_expiry IS NULL OR p_expiry<=clock_timestamp() THEN
        RAISE EXCEPTION 'invalid management session bounds';
    END IF;
    INSERT INTO aegaeon.runtime_management_session_scopes(namespace) VALUES(p_namespace) ON CONFLICT DO NOTHING;
    PERFORM 1 FROM aegaeon.runtime_management_session_scopes WHERE namespace=p_namespace FOR UPDATE;
    IF p_expiry<=clock_timestamp() THEN RAISE EXCEPTION 'expired management session'; END IF;
    IF EXISTS(SELECT FROM aegaeon.runtime_management_sessions WHERE namespace=p_namespace AND token_digest=p_digest) THEN
        RAISE EXCEPTION 'management session collision';
    END IF;
    -- Bounded opportunistic cleanup. Remaining expired rows count toward capacity
    -- and can be evicted; their presence never authenticates a request.
    DELETE FROM aegaeon.runtime_management_sessions WHERE ctid IN (
        SELECT ctid FROM aegaeon.runtime_management_sessions WHERE namespace=p_namespace AND expires_at<=clock_timestamp()
        ORDER BY expires_at LIMIT 4096 FOR UPDATE SKIP LOCKED
    );
    SELECT count(*) INTO retained FROM aegaeon.runtime_management_sessions WHERE namespace=p_namespace;
    IF retained>=p_capacity THEN
        DELETE FROM aegaeon.runtime_management_sessions WHERE token_digest IN (
            SELECT token_digest FROM aegaeon.runtime_management_sessions WHERE namespace=p_namespace
            ORDER BY created_at_epoch_secs,token_digest LIMIT retained-p_capacity+1
        ) AND namespace=p_namespace;
    END IF;
    -- A random-key collision aborts the entire statement, including any eviction.
    INSERT INTO aegaeon.runtime_management_sessions(namespace,token_digest,administrator_id,created_at_epoch_secs,expires_at)
        VALUES(p_namespace,p_digest,p_administrator,p_created,p_expiry);
END $$;

-- END ORGANIZATIONS COMPONENT runtime_management_sessions

-- BEGIN ORGANIZATIONS COMPONENT runtime_browser_sessions
-- Only session creation serializes on its namespace; ordinary authentication reads do not.
CREATE TABLE aegaeon.runtime_browser_session_scopes (
    namespace text COLLATE "C" PRIMARY KEY CHECK(octet_length(namespace) BETWEEN 1 AND 256),
    retained bigint NOT NULL DEFAULT 0 CHECK(retained>=0)
);
CREATE TABLE aegaeon.runtime_browser_sessions (
    namespace text COLLATE "C" NOT NULL REFERENCES aegaeon.runtime_browser_session_scopes(namespace),
    token_digest bytea NOT NULL CHECK(octet_length(token_digest)=32),
    subject_digest bytea NOT NULL CHECK(octet_length(subject_digest)=32),
    session_envelope bytea NOT NULL CHECK(octet_length(session_envelope)=65),
    payload text COLLATE "C" NOT NULL CHECK(octet_length(payload)<=65536),
    created_at_epoch_secs bigint NOT NULL CHECK(created_at_epoch_secs>=0),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY(namespace,token_digest)
);
CREATE INDEX runtime_browser_session_expiry_idx ON aegaeon.runtime_browser_sessions(namespace,expires_at);
CREATE INDEX runtime_browser_session_age_idx ON aegaeon.runtime_browser_sessions(namespace,created_at_epoch_secs,token_digest);

CREATE INDEX runtime_browser_session_subject_idx ON aegaeon.runtime_browser_sessions(namespace,subject_digest,expires_at);

CREATE INDEX runtime_browser_session_inventory_idx ON aegaeon.runtime_browser_sessions(namespace,subject_digest,(-((payload::jsonb->>'auth_time_epoch_secs')::bigint)),token_digest);

-- Counts are current transactional state, including rollback and cleanup.
CREATE FUNCTION aegaeon.count_runtime_browser_session() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        UPDATE aegaeon.runtime_browser_session_scopes SET retained=retained+1 WHERE namespace=NEW.namespace;
        RETURN NEW;
    ELSIF TG_OP='DELETE' THEN
        UPDATE aegaeon.runtime_browser_session_scopes SET retained=retained-1 WHERE namespace=OLD.namespace;
        RETURN OLD;
    END IF;
    IF NEW.namespace<>OLD.namespace OR NEW.token_digest<>OLD.token_digest THEN
        RAISE EXCEPTION 'browser session identity is immutable';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER runtime_browser_session_count AFTER INSERT OR DELETE ON aegaeon.runtime_browser_sessions
FOR EACH ROW EXECUTE FUNCTION aegaeon.count_runtime_browser_session();
CREATE TRIGGER runtime_browser_session_identity BEFORE UPDATE ON aegaeon.runtime_browser_sessions
FOR EACH ROW EXECUTE FUNCTION aegaeon.count_runtime_browser_session();

-- A bounded all-or-nothing bulk operation; no silent partial revocation.
CREATE FUNCTION aegaeon.delete_runtime_browser_sessions(p_namespace text,p_digest bytea,p_subject bytea)
RETURNS bigint LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE selected bytea[]; removed bigint;
BEGIN
    IF p_digest IS NULL AND p_subject IS NULL THEN RAISE EXCEPTION 'missing browser selector'; END IF;
    PERFORM 1 FROM aegaeon.runtime_browser_session_scopes WHERE namespace=p_namespace FOR UPDATE;
    SELECT ARRAY(SELECT token_digest FROM aegaeon.runtime_browser_sessions
        WHERE namespace=p_namespace AND (p_digest IS NULL OR token_digest=p_digest)
        AND (p_subject IS NULL OR subject_digest=p_subject) ORDER BY token_digest LIMIT 4097 FOR UPDATE) INTO selected;
    IF cardinality(selected)>4096 THEN RAISE EXCEPTION 'browser revocation exceeds batch bound'; END IF;
    DELETE FROM aegaeon.runtime_browser_sessions WHERE namespace=p_namespace AND token_digest=ANY(selected);
    GET DIAGNOSTICS removed=ROW_COUNT;
    RETURN removed;
END $$;

CREATE FUNCTION aegaeon.create_runtime_browser_session(
    p_namespace text,p_digest bytea,p_subject bytea,p_envelope bytea,p_payload text,p_created bigint,p_expiry timestamptz,p_capacity integer
) RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE retained bigint;
BEGIN
    IF p_capacity IS NULL OR p_capacity NOT BETWEEN 1 AND 1000000 OR p_created IS NULL OR p_created<0
       OR p_expiry IS NULL OR p_expiry<=clock_timestamp() THEN
        RAISE EXCEPTION 'invalid browser session bounds';
    END IF;
    INSERT INTO aegaeon.runtime_browser_session_scopes(namespace) VALUES(p_namespace) ON CONFLICT DO NOTHING;
    PERFORM 1 FROM aegaeon.runtime_browser_session_scopes WHERE namespace=p_namespace FOR UPDATE;
    IF p_expiry<=clock_timestamp() THEN RAISE EXCEPTION 'expired browser session'; END IF;
    IF EXISTS(SELECT FROM aegaeon.runtime_browser_sessions WHERE namespace=p_namespace AND token_digest=p_digest) THEN
        RAISE EXCEPTION 'browser session collision';
    END IF;
    -- Bounded opportunistic cleanup. Remaining expired rows count toward capacity
    -- and can be evicted; their presence never authenticates a request.
    DELETE FROM aegaeon.runtime_browser_sessions WHERE ctid IN (
        SELECT ctid FROM aegaeon.runtime_browser_sessions WHERE namespace=p_namespace AND expires_at<=clock_timestamp()
        ORDER BY expires_at LIMIT 4096 FOR UPDATE SKIP LOCKED
    );
    SELECT sc.retained INTO retained FROM aegaeon.runtime_browser_session_scopes sc WHERE namespace=p_namespace;
    IF retained-p_capacity+1>4096 THEN RAISE EXCEPTION 'browser capacity reduction exceeds batch bound'; END IF;
    IF retained>=p_capacity THEN
        DELETE FROM aegaeon.runtime_browser_sessions WHERE token_digest IN (
            SELECT token_digest FROM aegaeon.runtime_browser_sessions WHERE namespace=p_namespace
            ORDER BY created_at_epoch_secs,token_digest LIMIT retained-p_capacity+1
        ) AND namespace=p_namespace;
    END IF;
    -- A random-key collision aborts the entire statement, including any eviction.
    INSERT INTO aegaeon.runtime_browser_sessions(namespace,token_digest,subject_digest,session_envelope,payload,created_at_epoch_secs,expires_at)
        VALUES(p_namespace,p_digest,p_subject,p_envelope,p_payload,p_created,p_expiry);
END $$;

-- END ORGANIZATIONS COMPONENT runtime_browser_sessions

-- BEGIN ORGANIZATIONS COMPONENT runtime_par
-- Current PAR capabilities and their one-time authorization reservations.
-- The eventual code publication consumes the same row in its SQL transaction.
CREATE TABLE aegaeon.runtime_par_requests (
    namespace text COLLATE "C" NOT NULL CHECK(octet_length(namespace) BETWEEN 1 AND 256),
    token_digest bytea NOT NULL CHECK(octet_length(token_digest)=32),
    client_digest bytea NOT NULL CHECK(octet_length(client_digest)=32),
    payload text COLLATE "C" NOT NULL CHECK(octet_length(payload)<=1048576),
    continuation text COLLATE "C" CHECK(octet_length(continuation)=43),
    reservation_payload_digest bytea CHECK(octet_length(reservation_payload_digest)=32),
    CHECK((continuation IS NULL)=(reservation_payload_digest IS NULL)),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY(namespace,token_digest)
);
CREATE INDEX runtime_par_expiry_idx ON aegaeon.runtime_par_requests(namespace,expires_at);

CREATE FUNCTION aegaeon.reserve_runtime_par(
    p_namespace text,p_request bytea,p_client bytea,p_continuation text
) RETURNS TABLE(outcome integer,payload text,expiry bigint)
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE current_request aegaeon.runtime_par_requests%ROWTYPE;
BEGIN
    IF p_namespace IS NULL OR octet_length(p_namespace) NOT BETWEEN 1 AND 256
       OR p_request IS NULL OR octet_length(p_request)<>32
       OR p_client IS NULL OR octet_length(p_client)<>32
       OR p_continuation IS NULL OR octet_length(p_continuation)<>43 THEN
        RAISE EXCEPTION 'invalid PAR continuation';
    END IF;
    SELECT * INTO current_request FROM aegaeon.runtime_par_requests
        WHERE namespace=p_namespace AND token_digest=p_request FOR UPDATE;
    IF NOT FOUND OR current_request.expires_at<=clock_timestamp() THEN
        RETURN QUERY SELECT 1,NULL::text,NULL::bigint; RETURN;
    END IF;
    IF current_request.client_digest<>p_client THEN
        RETURN QUERY SELECT 2,NULL::text,NULL::bigint; RETURN;
    END IF;
    IF current_request.continuation IS NOT NULL THEN
        RETURN QUERY SELECT 1,NULL::text,NULL::bigint; RETURN;
    END IF;
    UPDATE aegaeon.runtime_par_requests SET continuation=p_continuation,
        reservation_payload_digest=sha256(convert_to(current_request.payload,'UTF8'))
        WHERE namespace=p_namespace AND token_digest=p_request;
    RETURN QUERY SELECT 0,current_request.payload,extract(epoch from current_request.expires_at)::bigint;
END $$;

-- END ORGANIZATIONS COMPONENT runtime_par

-- BEGIN ORGANIZATIONS COMPONENT runtime_authorization_codes
-- Current protocol capabilities; RP state/nonce rows are observations, not replay bans.
CREATE TABLE aegaeon.runtime_authorization_codes (
    namespace text COLLATE "C" NOT NULL CHECK(octet_length(namespace) BETWEEN 1 AND 256),
    token_digest bytea NOT NULL CHECK(octet_length(token_digest)=32),
    client_digest bytea NOT NULL CHECK(octet_length(client_digest)=32),
    payload text COLLATE "C" NOT NULL CHECK(octet_length(payload)<=1048576),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY(namespace,token_digest)
);
CREATE INDEX runtime_authorization_codes_expiry_idx ON aegaeon.runtime_authorization_codes(namespace,expires_at);

CREATE TABLE aegaeon.runtime_authorization_observations (
    namespace text COLLATE "C" NOT NULL CHECK(octet_length(namespace) BETWEEN 1 AND 256),
    kind smallint NOT NULL CHECK(kind IN (0,1)),
    token_digest bytea NOT NULL CHECK(octet_length(token_digest)=32),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY(namespace,kind,token_digest)
);
CREATE INDEX runtime_authorization_observations_expiry_idx ON aegaeon.runtime_authorization_observations(namespace,expires_at);

CREATE TABLE aegaeon.runtime_request_object_jtis (
    namespace text COLLATE "C" NOT NULL CHECK(octet_length(namespace) BETWEEN 1 AND 256),
    token_digest bytea NOT NULL CHECK(octet_length(token_digest)=32),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY(namespace,token_digest)
);
CREATE INDEX runtime_request_object_jtis_expiry_idx ON aegaeon.runtime_request_object_jtis(namespace,expires_at);

CREATE FUNCTION aegaeon.record_runtime_request_object_jti(p_namespace text,p_jti bytea,p_ttl_ms bigint)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF p_ttl_ms IS NULL OR p_ttl_ms NOT BETWEEN 1 AND 86400000 THEN
        RAISE EXCEPTION 'invalid Request Object replay retention';
    END IF;
    INSERT INTO aegaeon.runtime_request_object_jtis(namespace,token_digest,expires_at)
        VALUES(p_namespace,p_jti,clock_timestamp()+p_ttl_ms*interval '1 millisecond')
        ON CONFLICT(namespace,token_digest) DO UPDATE SET expires_at=clock_timestamp()+p_ttl_ms*interval '1 millisecond'
        WHERE runtime_request_object_jtis.expires_at<=clock_timestamp();
    RETURN FOUND;
END $$;

-- A signed PAR publishes its request and replay entry together.
CREATE FUNCTION aegaeon.publish_runtime_par(
    p_namespace text,p_request bytea,p_client bytea,p_payload text,p_expiry timestamptz,
    p_jti bytea,p_jti_ms bigint
) RETURNS integer LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF p_expiry IS NULL OR p_expiry<=clock_timestamp() THEN RETURN 4; END IF;
    INSERT INTO aegaeon.runtime_par_requests(namespace,token_digest,client_digest,payload,expires_at)
        VALUES(p_namespace,p_request,p_client,p_payload,p_expiry);
    IF p_jti IS NOT NULL AND NOT aegaeon.record_runtime_request_object_jti(p_namespace,p_jti,p_jti_ms) THEN
        RAISE EXCEPTION USING ERRCODE='P7103',MESSAGE='Request Object replay';
    END IF;
    IF p_expiry<=clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='P7104',MESSAGE='PAR expired';
    END IF;
    IF p_jti IS NOT NULL THEN
        UPDATE aegaeon.runtime_request_object_jtis
            SET expires_at=GREATEST(expires_at,clock_timestamp()+p_jti_ms*interval '1 millisecond')
            WHERE namespace=p_namespace AND token_digest=p_jti;
    END IF;
    RETURN 0;
EXCEPTION
    WHEN SQLSTATE 'P7103' THEN RETURN 3;
    WHEN SQLSTATE 'P7104' THEN RETURN 4;
END $$;

-- Lock order: PAR, JAR, code, state observation, nonce observation.
-- Custom conditions roll back the entire block, including a newly recorded JAR.
CREATE FUNCTION aegaeon.issue_runtime_authorization_code(
    p_namespace text,p_code bytea,p_client bytea,p_payload text,p_expiry_us bigint,
    p_state bytea,p_nonce bytea,p_observation_ms bigint,
    p_par bytea,p_continuation text,p_jti bytea,p_jti_ms bigint
) RETURNS integer LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE current_par aegaeon.runtime_par_requests%ROWTYPE;
    code_expiry timestamptz;
    observation_expiry timestamptz;
BEGIN
    IF p_expiry_us IS NULL OR p_expiry_us<0
       OR p_observation_ms IS NULL OR p_observation_ms NOT BETWEEN 1 AND 86400000
       OR (p_par IS NULL)<>(p_continuation IS NULL)
       OR (p_par IS NOT NULL AND (octet_length(p_par)<>32 OR octet_length(p_continuation)<>43)) THEN
        RAISE EXCEPTION 'invalid authorization code input';
    END IF;
    code_expiry:=timestamptz 'epoch'+(p_expiry_us/1000000)*interval '1 second'+(p_expiry_us%1000000)*interval '1 microsecond';
    IF p_par IS NOT NULL THEN
        SELECT * INTO current_par FROM aegaeon.runtime_par_requests
            WHERE namespace=p_namespace AND token_digest=p_par FOR UPDATE;
        IF NOT FOUND OR current_par.continuation IS DISTINCT FROM p_continuation
           OR current_par.client_digest IS DISTINCT FROM p_client
           OR current_par.reservation_payload_digest IS DISTINCT FROM sha256(convert_to(current_par.payload,'UTF8'))
           OR current_par.expires_at<=clock_timestamp() THEN
            RETURN 2;
        END IF;
    END IF;
    IF p_jti IS NOT NULL AND NOT aegaeon.record_runtime_request_object_jti(p_namespace,p_jti,p_jti_ms) THEN
        RETURN 3;
    END IF;
    INSERT INTO aegaeon.runtime_authorization_codes(namespace,token_digest,client_digest,payload,expires_at)
        VALUES(p_namespace,p_code,p_client,p_payload,code_expiry) ON CONFLICT DO NOTHING;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P7101',MESSAGE='code collision'; END IF;
    observation_expiry:=clock_timestamp()+p_observation_ms*interval '1 millisecond';
    IF p_state IS NOT NULL THEN
        INSERT INTO aegaeon.runtime_authorization_observations VALUES(p_namespace,0,p_state,observation_expiry)
            ON CONFLICT(namespace,kind,token_digest) DO UPDATE
            SET expires_at=GREATEST(runtime_authorization_observations.expires_at,EXCLUDED.expires_at);
    END IF;
    IF p_nonce IS NOT NULL THEN
        INSERT INTO aegaeon.runtime_authorization_observations VALUES(p_namespace,1,p_nonce,observation_expiry)
            ON CONFLICT(namespace,kind,token_digest) DO UPDATE
            SET expires_at=GREATEST(runtime_authorization_observations.expires_at,EXCLUDED.expires_at);
    END IF;
    -- Recheck after every possible lock wait. Expired inputs publish no code/marker/JAR.
    IF code_expiry<=clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='P7104',MESSAGE='code expired';
    END IF;
    IF p_jti IS NOT NULL THEN
        UPDATE aegaeon.runtime_request_object_jtis
            SET expires_at=GREATEST(expires_at,clock_timestamp()+p_jti_ms*interval '1 millisecond')
            WHERE namespace=p_namespace AND token_digest=p_jti;
    END IF;
    IF p_par IS NOT NULL THEN
        IF current_par.expires_at<=clock_timestamp() THEN
            RAISE EXCEPTION USING ERRCODE='P7102',MESSAGE='PAR expired';
        END IF;
        DELETE FROM aegaeon.runtime_par_requests WHERE namespace=p_namespace AND token_digest=p_par;
    END IF;
    RETURN 0;
EXCEPTION
    WHEN SQLSTATE 'P7101' THEN RETURN 1;
    WHEN SQLSTATE 'P7102' THEN RETURN 2;
    WHEN SQLSTATE 'P7104' THEN RETURN 4;
END $$;

-- END ORGANIZATIONS COMPONENT runtime_authorization_codes

-- BEGIN ORGANIZATIONS COMPONENT runtime_oidc_sessions
-- Current OIDC bindings and bounded logout delivery receipts.
-- Active sessions retain the existing lifetime semantics; logout sets the deadline.
CREATE TABLE aegaeon.runtime_oidc_sessions (
    namespace text COLLATE "C" NOT NULL CHECK(octet_length(namespace) BETWEEN 1 AND 256),
    sid uuid NOT NULL,
    user_id text COLLATE "C" NOT NULL CHECK(octet_length(user_id)>0),
    auth_digest bytea NOT NULL CHECK(octet_length(auth_digest)=32),
    logout_jti uuid,
    logged_out_at bigint CHECK(logged_out_at>=0),
    expires_at timestamptz,
    CHECK((logout_jti IS NULL)=(logged_out_at IS NULL) AND (logout_jti IS NULL)=(expires_at IS NULL)),
    PRIMARY KEY(namespace,sid)
);
CREATE INDEX runtime_oidc_sessions_user_idx ON aegaeon.runtime_oidc_sessions(namespace,user_id,sid) WHERE logout_jti IS NULL;
CREATE INDEX runtime_oidc_sessions_expiry_idx ON aegaeon.runtime_oidc_sessions(namespace,expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE aegaeon.runtime_oidc_auth_bindings (
    namespace text COLLATE "C" NOT NULL,
    auth_digest bytea NOT NULL CHECK(octet_length(auth_digest)=32),
    sid uuid NOT NULL,
    PRIMARY KEY(namespace,auth_digest),
    UNIQUE(namespace,sid),
    FOREIGN KEY(namespace,sid) REFERENCES aegaeon.runtime_oidc_sessions(namespace,sid) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE aegaeon.runtime_oidc_clients (
    namespace text COLLATE "C" NOT NULL,
    sid uuid NOT NULL,
    client_id text COLLATE "C" NOT NULL CHECK(octet_length(client_id)>0),
    delivery text COLLATE "C" CHECK(octet_length(delivery)<=65536),
    PRIMARY KEY(namespace,sid,client_id),
    FOREIGN KEY(namespace,sid) REFERENCES aegaeon.runtime_oidc_sessions(namespace,sid)
);

-- Exact mode is for an already signed ID Token: never silently substitute its sid.
-- Lock order is auth binding, session, client. Logout never updates an auth binding.
CREATE FUNCTION aegaeon.bind_runtime_oidc_session(
    p_namespace text,p_auth bytea,p_user text,p_sid uuid,p_client text,p_exact boolean
) RETURNS uuid LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE selected_sid uuid;
    current_session aegaeon.runtime_oidc_sessions%ROWTYPE;
BEGIN
    IF p_user IS NULL OR p_user='' OR p_sid IS NULL OR p_exact IS NULL OR p_client='' THEN
        RAISE EXCEPTION 'invalid OIDC binding';
    END IF;
    INSERT INTO aegaeon.runtime_oidc_auth_bindings(namespace,auth_digest,sid)
        VALUES(p_namespace,p_auth,p_sid) ON CONFLICT(namespace,auth_digest) DO NOTHING;
    SELECT b.sid INTO STRICT selected_sid FROM aegaeon.runtime_oidc_auth_bindings b
        WHERE b.namespace=p_namespace AND b.auth_digest=p_auth FOR UPDATE;
    SELECT * INTO current_session FROM aegaeon.runtime_oidc_sessions s
        WHERE s.namespace=p_namespace AND s.sid=selected_sid FOR UPDATE;
    IF FOUND THEN
        IF current_session.user_id<>p_user OR current_session.auth_digest<>p_auth THEN
            RAISE EXCEPTION 'OIDC binding identity mismatch';
        END IF;
        IF current_session.logout_jti IS NOT NULL THEN
            IF selected_sid=p_sid THEN RAISE EXCEPTION 'OIDC session already closed'; END IF;
            INSERT INTO aegaeon.runtime_oidc_sessions(namespace,sid,user_id,auth_digest)
                VALUES(p_namespace,p_sid,p_user,p_auth);
            UPDATE aegaeon.runtime_oidc_auth_bindings b SET sid=p_sid
                WHERE b.namespace=p_namespace AND b.auth_digest=p_auth;
            selected_sid:=p_sid;
        ELSIF p_exact AND selected_sid<>p_sid THEN
            RAISE EXCEPTION 'OIDC binding changed before grant commit';
        END IF;
    ELSE
        IF selected_sid<>p_sid THEN RAISE EXCEPTION 'OIDC binding parent missing'; END IF;
        INSERT INTO aegaeon.runtime_oidc_sessions(namespace,sid,user_id,auth_digest)
            VALUES(p_namespace,p_sid,p_user,p_auth);
    END IF;
    IF p_client IS NOT NULL THEN
        INSERT INTO aegaeon.runtime_oidc_clients(namespace,sid,client_id)
            VALUES(p_namespace,selected_sid,p_client) ON CONFLICT DO NOTHING;
    END IF;
    RETURN selected_sid;
END $$;

CREATE FUNCTION aegaeon.add_runtime_oidc_client(p_namespace text,p_sid uuid,p_client text)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE current_session aegaeon.runtime_oidc_sessions%ROWTYPE;
BEGIN
    SELECT * INTO current_session FROM aegaeon.runtime_oidc_sessions s
        WHERE s.namespace=p_namespace AND s.sid=p_sid FOR UPDATE;
    IF NOT FOUND OR current_session.logout_jti IS NOT NULL THEN RETURN false; END IF;
    INSERT INTO aegaeon.runtime_oidc_clients(namespace,sid,client_id)
        VALUES(p_namespace,p_sid,p_client) ON CONFLICT DO NOTHING;
    RETURN true;
END $$;

CREATE FUNCTION aegaeon.logout_runtime_oidc_session(p_namespace text,p_sid uuid,p_jti uuid,p_ttl bigint)
RETURNS TABLE(sid uuid,user_id text,event_jti uuid,clients text[])
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE current_session aegaeon.runtime_oidc_sessions%ROWTYPE;
    now_seconds bigint;
    client_count bigint; client_bytes bigint;
BEGIN
    IF p_jti IS NULL OR p_ttl IS NULL OR p_ttl NOT BETWEEN 1 AND 86400 THEN
        RAISE EXCEPTION 'invalid OIDC logout';
    END IF;
    SELECT * INTO current_session FROM aegaeon.runtime_oidc_sessions s
        WHERE s.namespace=p_namespace AND s.sid=p_sid FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    now_seconds:=floor(extract(epoch from clock_timestamp()))::bigint;
    IF current_session.logout_jti IS NOT NULL THEN
        IF current_session.logged_out_at>now_seconds THEN RAISE EXCEPTION 'OIDC logout clock precedes event'; END IF;
        IF current_session.expires_at<=clock_timestamp() THEN RETURN; END IF;
    ELSE
        UPDATE aegaeon.runtime_oidc_sessions s SET logout_jti=p_jti,logged_out_at=now_seconds,
            expires_at=timestamptz 'epoch'+(now_seconds+p_ttl)*interval '1 second'
            WHERE s.namespace=p_namespace AND s.sid=p_sid RETURNING s.* INTO current_session;
    END IF;
    SELECT count(*),coalesce(sum(octet_length(c.client_id)),0) INTO client_count,client_bytes
        FROM (SELECT c.client_id FROM aegaeon.runtime_oidc_clients c
            WHERE c.namespace=p_namespace AND c.sid=p_sid ORDER BY c.client_id LIMIT 1025) c;
    IF client_count>1024 OR client_bytes>1048576 OR octet_length(current_session.user_id)>65536 THEN
        RAISE EXCEPTION 'OIDC logout event exceeds result bound';
    END IF;
    RETURN QUERY SELECT current_session.sid,current_session.user_id,current_session.logout_jti,
        ARRAY(SELECT c.client_id FROM aegaeon.runtime_oidc_clients c
            WHERE c.namespace=p_namespace AND c.sid=p_sid ORDER BY c.client_id);
END $$;

CREATE FUNCTION aegaeon.logout_runtime_oidc_auth_session(p_namespace text,p_auth bytea,p_jti uuid,p_ttl bigint)
RETURNS TABLE(sid uuid,user_id text,event_jti uuid,clients text[])
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE selected_sid uuid;
BEGIN
    SELECT b.sid INTO selected_sid FROM aegaeon.runtime_oidc_auth_bindings b
        WHERE b.namespace=p_namespace AND b.auth_digest=p_auth FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    RETURN QUERY SELECT * FROM aegaeon.logout_runtime_oidc_session(p_namespace,selected_sid,p_jti,p_ttl);
END $$;

CREATE FUNCTION aegaeon.logout_runtime_oidc_user(p_namespace text,p_user text,p_ttl bigint)
RETURNS TABLE(sid uuid,user_id text,event_jti uuid,clients text[])
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE selected_sid uuid; item record; result_count integer:=0; result_bytes bigint:=0;
BEGIN
    FOR selected_sid IN SELECT s.sid FROM aegaeon.runtime_oidc_sessions s
        WHERE s.namespace=p_namespace AND s.user_id=p_user AND s.logout_jti IS NULL
        ORDER BY s.sid LIMIT 129 FOR UPDATE LOOP
        result_count:=result_count+1;
        IF result_count>128 THEN RAISE EXCEPTION 'OIDC logout exceeds session bound'; END IF;
        FOR item IN SELECT * FROM aegaeon.logout_runtime_oidc_session(p_namespace,selected_sid,gen_random_uuid(),p_ttl) LOOP
            result_bytes:=result_bytes+pg_column_size(item);
            IF result_bytes>4194304 THEN RAISE EXCEPTION 'OIDC logout exceeds byte bound'; END IF;
            sid:=item.sid; user_id:=item.user_id; event_jti:=item.event_jti; clients:=item.clients;
            RETURN NEXT;
        END LOOP;
    END LOOP;
END $$;

-- END ORGANIZATIONS COMPONENT runtime_oidc_sessions

-- BEGIN ORGANIZATIONS COMPONENT runtime_token_grants
-- Current online token authority. Missing roots never imply permission.
-- Integer microsecond deadlines avoid floating-point SQL timestamp conversion.
-- One current subject-wide token generation supports atomic logout/revoke-all.
-- It is restored with this database, not an independent recovery ledger.
CREATE TABLE aegaeon.runtime_token_subjects (
    namespace text COLLATE "C" NOT NULL CHECK(octet_length(namespace) BETWEEN 1 AND 256),
    subject_digest bytea NOT NULL CHECK(octet_length(subject_digest)=32),
    generation uuid NOT NULL,
    PRIMARY KEY(namespace,subject_digest)
);

CREATE TABLE aegaeon.runtime_refresh_families (
    namespace text COLLATE "C" NOT NULL CHECK(octet_length(namespace) BETWEEN 1 AND 256),
    id text COLLATE "C" NOT NULL CHECK(id ~ '^[A-Za-z0-9_-]{43}$'),
    version integer NOT NULL CHECK(version=1),
    client_digest bytea NOT NULL CHECK(octet_length(client_digest)=32),
    subject_digest bytea NOT NULL CHECK(octet_length(subject_digest)=32),
    subject_generation uuid NOT NULL,
    revoked boolean NOT NULL DEFAULT false,
    expires_us bigint NOT NULL CHECK(expires_us>0),
    PRIMARY KEY(namespace,id),
    FOREIGN KEY(namespace,subject_digest) REFERENCES aegaeon.runtime_token_subjects(namespace,subject_digest)
);
CREATE INDEX runtime_refresh_families_subject_idx ON aegaeon.runtime_refresh_families(namespace,subject_digest,id);
CREATE INDEX runtime_refresh_families_expiry_idx ON aegaeon.runtime_refresh_families(namespace,expires_us,id);

CREATE TABLE aegaeon.runtime_exchange_roots (
    namespace text COLLATE "C" NOT NULL CHECK(octet_length(namespace) BETWEEN 1 AND 256),
    id text COLLATE "C" NOT NULL CHECK(id ~ '^exchange-root:[0-9a-f-]{36}$'),
    client_digest bytea NOT NULL CHECK(octet_length(client_digest)=32),
    subject_digest bytea NOT NULL CHECK(octet_length(subject_digest)=32),
    subject_generation uuid NOT NULL,
    family_id text COLLATE "C",
    revoked boolean NOT NULL DEFAULT false,
    expires_us bigint NOT NULL CHECK(expires_us>0),
    PRIMARY KEY(namespace,id),
    FOREIGN KEY(namespace,subject_digest) REFERENCES aegaeon.runtime_token_subjects(namespace,subject_digest),
    FOREIGN KEY(namespace,family_id) REFERENCES aegaeon.runtime_refresh_families(namespace,id) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX runtime_exchange_roots_subject_idx ON aegaeon.runtime_exchange_roots(namespace,subject_digest,id);
CREATE INDEX runtime_exchange_roots_family_idx ON aegaeon.runtime_exchange_roots(namespace,family_id);
CREATE INDEX runtime_exchange_roots_expiry_idx ON aegaeon.runtime_exchange_roots(namespace,expires_us,id);

CREATE TABLE aegaeon.runtime_token_capabilities (
    namespace text COLLATE "C" NOT NULL CHECK(octet_length(namespace) BETWEEN 1 AND 256),
    token_digest bytea NOT NULL CHECK(octet_length(token_digest)=32),
    kind smallint NOT NULL CHECK(kind IN (1,2)), -- access / refresh
    payload text COLLATE "C" NOT NULL CHECK(octet_length(payload) BETWEEN 1 AND 1048576),
    metadata text COLLATE "C" CHECK(octet_length(metadata) BETWEEN 1 AND 1048576),
    client_digest bytea NOT NULL CHECK(octet_length(client_digest)=32),
    subject_digest bytea NOT NULL CHECK(octet_length(subject_digest)=32),
    subject_generation uuid NOT NULL,
    family_id text COLLATE "C",
    root_id text COLLATE "C",
    refresh_parent_digest bytea CHECK(octet_length(refresh_parent_digest)=32),
    rotated boolean NOT NULL DEFAULT false,
    revoked boolean NOT NULL DEFAULT false,
    expires_us bigint NOT NULL CHECK(expires_us>0),
    CHECK((kind=1 AND metadata IS NOT NULL AND NOT rotated) OR (kind=2 AND metadata IS NULL AND family_id IS NOT NULL AND refresh_parent_digest IS NULL)),
    CHECK(refresh_parent_digest IS NULL OR family_id IS NOT NULL),
    PRIMARY KEY(namespace,token_digest),
    FOREIGN KEY(namespace,subject_digest) REFERENCES aegaeon.runtime_token_subjects(namespace,subject_digest),
    FOREIGN KEY(namespace,family_id) REFERENCES aegaeon.runtime_refresh_families(namespace,id),
    FOREIGN KEY(namespace,root_id) REFERENCES aegaeon.runtime_exchange_roots(namespace,id)
);
CREATE INDEX runtime_token_capabilities_subject_idx ON aegaeon.runtime_token_capabilities(namespace,subject_digest,kind,token_digest);
CREATE INDEX runtime_token_capabilities_family_idx ON aegaeon.runtime_token_capabilities(namespace,family_id,token_digest);
CREATE INDEX runtime_token_capabilities_root_idx ON aegaeon.runtime_token_capabilities(namespace,root_id,token_digest);
CREATE INDEX runtime_token_capabilities_parent_idx ON aegaeon.runtime_token_capabilities(namespace,refresh_parent_digest,token_digest);
CREATE INDEX runtime_token_capabilities_expiry_idx ON aegaeon.runtime_token_capabilities(namespace,expires_us,token_digest);

-- Keyset inventory groups access descendants by their refresh parent.
CREATE INDEX runtime_token_capabilities_inventory_idx ON aegaeon.runtime_token_capabilities(namespace,subject_digest,kind,(coalesce(refresh_parent_digest,token_digest)),token_digest);

-- END ORGANIZATIONS COMPONENT runtime_token_grants

-- BEGIN ORGANIZATIONS COMPONENT runtime_device_codes
-- Current device authorization and polling state. No raw device/user code is stored.
CREATE TABLE aegaeon.runtime_device_codes (
    namespace text COLLATE "C" NOT NULL CHECK(octet_length(namespace) BETWEEN 1 AND 256),
    device_digest bytea NOT NULL CHECK(octet_length(device_digest)=32),
    user_digest bytea NOT NULL CHECK(octet_length(user_digest)=32),
    client_id text COLLATE "C" NOT NULL CHECK(octet_length(client_id) BETWEEN 1 AND 4096),
    scope text COLLATE "C" CHECK(octet_length(scope)<=65536),
    resource text COLLATE "C" CHECK(octet_length(resource)<=8192),
    environment_id text COLLATE "C" CHECK(octet_length(environment_id)<=4096),
    status smallint NOT NULL DEFAULT 0 CHECK(status IN (0,1,2)),
    subject text COLLATE "C" CHECK(octet_length(subject) BETWEEN 1 AND 4096),
    expires_us bigint NOT NULL CHECK(expires_us>0),
    last_poll_us bigint CHECK(last_poll_us>0),
    interval_secs bigint NOT NULL CHECK(interval_secs BETWEEN 0 AND 9223372036854),
    CHECK((status=1)=(subject IS NOT NULL)),
    PRIMARY KEY(namespace,device_digest),
    UNIQUE(namespace,user_digest)
);
CREATE INDEX runtime_device_codes_expiry_idx ON aegaeon.runtime_device_codes(namespace,expires_us,device_digest);

-- END ORGANIZATIONS COMPONENT runtime_device_codes

-- BEGIN ORGANIZATIONS COMPONENT runtime_jwks_admission
-- Current retained kid bindings and one bounded remote-fetch owner per trust URI.
-- Cached HTTP bodies remain disposable; neither table is a mutation journal.
CREATE TABLE aegaeon.runtime_jwks_bindings (
    namespace text COLLATE "C" NOT NULL CHECK(octet_length(namespace) BETWEEN 1 AND 256),
    uri_digest bytea NOT NULL CHECK(octet_length(uri_digest)=32),
    bindings text COLLATE "C" NOT NULL CHECK(octet_length(bindings) BETWEEN 2 AND 1048576),
    body_digest bytea NOT NULL CHECK(octet_length(body_digest)=32),
    admission_expires_us bigint NOT NULL CHECK(admission_expires_us>0),
    expires_us bigint NOT NULL CHECK(expires_us>=admission_expires_us),
    PRIMARY KEY(namespace,uri_digest)
);
CREATE INDEX runtime_jwks_bindings_expiry_idx ON aegaeon.runtime_jwks_bindings(namespace,expires_us,uri_digest);
CREATE TABLE aegaeon.runtime_jwks_fetches (
    namespace text COLLATE "C" NOT NULL CHECK(octet_length(namespace) BETWEEN 1 AND 256),
    uri_digest bytea NOT NULL CHECK(octet_length(uri_digest)=32),
    failures bigint NOT NULL DEFAULT 0 CHECK(failures BETWEEN 0 AND 4294967295),
    open_until_us bigint CHECK(open_until_us>0),
    owner uuid,
    lease_until_us bigint CHECK(lease_until_us>0),
    expires_us bigint NOT NULL CHECK(expires_us>0),
    CHECK((owner IS NULL)=(lease_until_us IS NULL)),
    PRIMARY KEY(namespace,uri_digest)
);
CREATE INDEX runtime_jwks_fetches_expiry_idx ON aegaeon.runtime_jwks_fetches(namespace,expires_us,uri_digest);

-- END ORGANIZATIONS COMPONENT runtime_jwks_admission

-- BEGIN ORGANIZATIONS COMPONENT runtime_lifecycle
-- Lifecycle selection changes only during an operator-controlled activation.
-- One shared session lock per runtime connection excludes concurrent activation.
CREATE SCHEMA aegaeon_lifecycle AUTHORIZATION aegaeon_subject_owner;
DO $lifecycle$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
CREATE TABLE aegaeon_lifecycle.current (
    singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
    deployment_id uuid NOT NULL CHECK(deployment_id <> '00000000-0000-0000-0000-000000000000'),
    generation uuid NOT NULL CHECK(generation <> '00000000-0000-0000-0000-000000000000'),
    activated_at timestamptz NOT NULL,
    assertions_after timestamptz NOT NULL,
    request_objects_after timestamptz NOT NULL,
    dpop_after timestamptz NOT NULL,
    proof_policy jsonb NOT NULL,
    operation_id uuid NOT NULL CHECK(operation_id <> '00000000-0000-0000-0000-000000000000')
);
CREATE TABLE aegaeon_lifecycle.activations (
    operation_id uuid PRIMARY KEY,
    deployment_id uuid NOT NULL,
    previous_generation uuid,
    generation uuid NOT NULL UNIQUE,
    activated_at timestamptz NOT NULL,
    assertions_after timestamptz NOT NULL,
    request_objects_after timestamptz NOT NULL,
    dpop_after timestamptz NOT NULL,
    proof_policy jsonb NOT NULL,
    actor text NOT NULL
);
ALTER TABLE aegaeon_lifecycle.current OWNER TO aegaeon_subject_owner;
ALTER TABLE aegaeon_lifecycle.activations OWNER TO aegaeon_subject_owner;
REVOKE ALL ON ALL TABLES IN SCHEMA aegaeon_lifecycle FROM PUBLIC;

EXECUTE $definition$
CREATE FUNCTION aegaeon_lifecycle.activate_v1(deployment uuid, previous uuid, next_generation uuid, operation uuid,
 proof_policy jsonb DEFAULT '{"assertion_window":3600,"request_object_window":3600,"clock_error":300}'::jsonb)
RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE selected aegaeon_lifecycle.current%ROWTYPE; activated timestamptz;
 assertion_window integer; request_window integer; clock_error integer;
 assertion_end timestamptz; request_end timestamptz; dpop_end timestamptz;
 field text; virgin boolean := false;
BEGIN
  IF deployment IS NULL OR next_generation IS NULL OR operation IS NULL
    OR deployment='00000000-0000-0000-0000-000000000000'
    OR next_generation='00000000-0000-0000-0000-000000000000'
    OR operation='00000000-0000-0000-0000-000000000000'
    OR next_generation IS NOT DISTINCT FROM previous THEN
    RAISE EXCEPTION 'invalid lifecycle selection';
  END IF;
  IF proof_policy IS NULL OR jsonb_typeof(proof_policy)<>'object'
    OR proof_policy-ARRAY['assertion_window','request_object_window','clock_error','initial_install']<>'{}'::jsonb THEN
    RAISE EXCEPTION 'invalid proof activation policy';
  END IF;
  FOREACH field IN ARRAY ARRAY['assertion_window','request_object_window','clock_error'] LOOP
    IF jsonb_typeof(proof_policy->field) IS DISTINCT FROM 'number'
      OR (proof_policy->>field) !~ '^[0-9]{1,4}$' THEN
      RAISE EXCEPTION 'invalid proof activation bound';
    END IF;
  END LOOP;
  IF proof_policy ? 'initial_install' THEN
    IF jsonb_typeof(proof_policy->'initial_install') IS DISTINCT FROM 'boolean' THEN
      RAISE EXCEPTION 'invalid initial installation assertion';
    END IF;
    virgin := (proof_policy->>'initial_install')::boolean;
  END IF;
  assertion_window := (proof_policy->>'assertion_window')::integer;
  request_window := (proof_policy->>'request_object_window')::integer;
  clock_error := (proof_policy->>'clock_error')::integer;
  IF assertion_window NOT BETWEEN 1 AND 3600 OR request_window NOT BETWEEN 1 AND 3600
    OR clock_error NOT BETWEEN 0 AND 3600 THEN
    RAISE EXCEPTION 'proof activation bound outside supported range';
  END IF;
  -- Database-local fixed key, separate from domain locks. No blocking lock queue.
  IF NOT pg_try_advisory_xact_lock(1095189836, 1) THEN
    RAISE EXCEPTION USING ERRCODE='55006', MESSAGE='runtime connections still present';
  END IF;
  SELECT * INTO selected FROM aegaeon_lifecycle.current WHERE singleton FOR UPDATE;
  IF selected.generation IS DISTINCT FROM previous
    OR (selected.deployment_id IS NOT NULL AND selected.deployment_id<>deployment) THEN
    RAISE EXCEPTION 'lifecycle predecessor mismatch';
  END IF;
  activated:=clock_timestamp();
  -- Empty restored data cannot establish that no proof was ever accepted.
  -- Only an explicit operator assertion of first-ever installation can omit
  -- the recovery wait. The receipt retains this trusted operational premise.
  IF virgin THEN
    IF previous IS NOT NULL OR selected.generation IS NOT NULL
      OR to_regclass('aegaeon.environments') IS NULL THEN
      RAISE EXCEPTION 'initial installation requires an unselected empty application';
    END IF;
    IF EXISTS(SELECT FROM aegaeon.environments) THEN
      RAISE EXCEPTION 'initial installation requires an empty application';
    END IF;
  END IF;
  assertion_end := activated + make_interval(secs => CASE WHEN virgin THEN 0 ELSE assertion_window+300+4*clock_error+1 END);
  request_end := activated + make_interval(secs => CASE WHEN virgin THEN 0 ELSE request_window+300+4*clock_error+1 END);
  dpop_end := activated + make_interval(secs => CASE WHEN virgin THEN 0 ELSE 600+4*clock_error+1 END);
  INSERT INTO aegaeon_lifecycle.activations
    VALUES(operation,deployment,previous,next_generation,activated,assertion_end,request_end,dpop_end,proof_policy,session_user);
  INSERT INTO aegaeon_lifecycle.current(singleton,deployment_id,generation,activated_at,assertions_after,request_objects_after,dpop_after,proof_policy,operation_id)
    VALUES(true,deployment,next_generation,activated,assertion_end,request_end,dpop_end,proof_policy,operation)
    ON CONFLICT(singleton) DO UPDATE SET generation=EXCLUDED.generation,
      activated_at=EXCLUDED.activated_at,assertions_after=EXCLUDED.assertions_after,
      request_objects_after=EXCLUDED.request_objects_after,dpop_after=EXCLUDED.dpop_after,
      proof_policy=EXCLUDED.proof_policy,operation_id=EXCLUDED.operation_id;
  RETURN activated;
END
$function$;
$definition$;
ALTER FUNCTION aegaeon_lifecycle.activate_v1(uuid,uuid,uuid,uuid,jsonb) OWNER TO aegaeon_subject_owner;
REVOKE ALL ON FUNCTION aegaeon_lifecycle.activate_v1(uuid,uuid,uuid,uuid,jsonb) FROM PUBLIC;
GRANT USAGE ON SCHEMA aegaeon_lifecycle TO aegaeon_subject_maintenance;
GRANT SELECT ON ALL TABLES IN SCHEMA aegaeon_lifecycle TO aegaeon_subject_maintenance;
GRANT EXECUTE ON FUNCTION aegaeon_lifecycle.activate_v1(uuid,uuid,uuid,uuid,jsonb) TO aegaeon_subject_maintenance;


RESET ROLE;
END
$lifecycle$;

-- END ORGANIZATIONS COMPONENT runtime_lifecycle

-- BEGIN ORGANIZATIONS COMPONENT catalog
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
DO $catalog$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
EXECUTE $definition$
CREATE OR REPLACE FUNCTION aegaeon.subject_history_physical_catalog(runtime_name text)
RETURNS TABLE(row_key text, row_text text)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp
AS $function$
 WITH protected_relations AS (
   SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='aegaeon' AND c.relname IN ('environments','end_users','end_user_password_credentials','end_user_profiles','user_attribute_sources','lti_registrations','lti_registration_revisions','lti_identifiers','lti_launch_intents','audit_events',
      'subject_ownership_namespaces','subject_ownership_adoptions','end_user_identity_owners','end_user_subject_reservations','authorization_domains','authorization_domain_targets','application_organizations','organization_role_definitions','organization_memberships','organization_authority_events','organization_authority_outbox','organization_authority_receipts','organization_operator_grants','organization_client_bindings','organization_invitations','organization_invitation_challenges','organization_identity_requests','organization_admin_access_grants','organization_import_operations','organization_creation_receipts','subject_history_restorations','subject_history_restoration_pages')
   UNION SELECT relid FROM pg_catalog.pg_partition_tree('aegaeon.audit_events'::regclass)
   UNION SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.relname='atlas_schema_revisions' AND n.nspname IN ('public','aegaeon')
 ), rows(kind, key, value) AS (
   SELECT 'namespace', n.oid::text, pg_catalog.to_jsonb(n) FROM pg_catalog.pg_namespace n WHERE n.nspname='aegaeon'
   UNION ALL SELECT 'relation',c.oid::text,pg_catalog.jsonb_build_object(
      'oid',c.oid,'relname',c.relname,'relnamespace',c.relnamespace,'reltype',c.reltype,
      'relowner',c.relowner,'relkind',c.relkind,'relpersistence',c.relpersistence,
      'relispartition',c.relispartition,'relpartbound',c.relpartbound::text,
      'relrowsecurity',c.relrowsecurity,'relforcerowsecurity',c.relforcerowsecurity,
      'relreplident',c.relreplident,'relacl',c.relacl,'reloptions',c.reloptions)
      FROM pg_catalog.pg_class c WHERE c.oid IN (SELECT oid FROM protected_relations)
   UNION ALL SELECT 'column',a.attrelid::text||':'||a.attnum::text,pg_catalog.to_jsonb(a) FROM pg_catalog.pg_attribute a WHERE a.attrelid IN (SELECT oid FROM protected_relations) AND a.attnum>0
   UNION ALL SELECT 'default',d.oid::text,pg_catalog.to_jsonb(d)||pg_catalog.jsonb_build_object('expression',pg_catalog.pg_get_expr(d.adbin,d.adrelid)) FROM pg_catalog.pg_attrdef d WHERE d.adrelid IN (SELECT oid FROM protected_relations)
   UNION ALL SELECT 'type',t.oid::text,pg_catalog.to_jsonb(t) FROM pg_catalog.pg_type t WHERE t.oid IN (SELECT atttypid FROM pg_catalog.pg_attribute WHERE attrelid IN (SELECT oid FROM protected_relations))
   UNION ALL SELECT 'collation',c.oid::text,pg_catalog.to_jsonb(c) FROM pg_catalog.pg_collation c WHERE c.oid IN (SELECT attcollation FROM pg_catalog.pg_attribute WHERE attrelid IN (SELECT oid FROM protected_relations))
   UNION ALL SELECT 'constraint',c.oid::text,pg_catalog.to_jsonb(c)||pg_catalog.jsonb_build_object('definition',pg_catalog.pg_get_constraintdef(c.oid,true)) FROM pg_catalog.pg_constraint c WHERE c.conrelid IN (SELECT oid FROM protected_relations) OR c.confrelid IN (SELECT oid FROM protected_relations)
   UNION ALL SELECT 'index',i.indexrelid::text,pg_catalog.to_jsonb(i)||pg_catalog.jsonb_build_object('definition',pg_catalog.pg_get_indexdef(i.indexrelid)) FROM pg_catalog.pg_index i WHERE i.indrelid IN (SELECT oid FROM protected_relations)
   UNION ALL SELECT 'trigger',t.oid::text,pg_catalog.to_jsonb(t)||pg_catalog.jsonb_build_object('definition',pg_catalog.pg_get_triggerdef(t.oid,true)) FROM pg_catalog.pg_trigger t WHERE t.tgrelid IN (SELECT oid FROM protected_relations)
   UNION ALL SELECT 'partition',i.inhrelid::text||':'||i.inhparent::text,pg_catalog.to_jsonb(i) FROM pg_catalog.pg_inherits i WHERE i.inhrelid IN (SELECT oid FROM protected_relations)
   UNION ALL SELECT 'function',p.oid::text,pg_catalog.to_jsonb(p)||pg_catalog.jsonb_build_object('definition',pg_catalog.pg_get_functiondef(p.oid),'acl',
      (SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('grantee',COALESCE(r.rolname,'PUBLIC'),'privilege',a.privilege_type,'grantable',a.is_grantable) ORDER BY a.grantee,a.privilege_type)
       FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee)) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='aegaeon' AND (p.proname LIKE 'subject_history_%' OR p.proname LIKE 'subject_ownership_%' OR p.proname IN ('restore_subject_history_page_v1','organization_creation_record_v1','organization_import_hold_guard','organization_identity_guard','organization_identity_credential_guard','organization_identity_policy_guard','organization_identity_profile_guard','organization_support_policy_guard','organization_admin_access_guard','organization_snapshot_history_v1','organization_import_target_v1','organization_import_hold_guard','organization_import_prepared_rows_v1','organization_import_operation_v1','organization_import_begin_v1','organization_import_row_v1','organization_import_finish_v1') OR p.proname IN ('inventory_subject_ownership_history_v1','adopt_subject_ownership_history_v1','validate_subject_ownership_namespace_v1'))
   UNION ALL SELECT 'role',r.oid::text,pg_catalog.to_jsonb(r) FROM pg_catalog.pg_roles r
   UNION ALL SELECT 'membership',m.roleid::text||':'||m.member::text||':'||m.grantor::text,pg_catalog.to_jsonb(m) FROM pg_catalog.pg_auth_members m
   UNION ALL SELECT 'parameter_acl',p.oid::text,pg_catalog.to_jsonb(p) FROM pg_catalog.pg_parameter_acl p
   UNION ALL SELECT 'atlas_revision',r.row_key,r.row_text::jsonb FROM aegaeon.subject_history_revision_rows() r
   UNION ALL SELECT 'runtime_role',runtime_name,pg_catalog.jsonb_build_object('runtime_role',runtime_name)
 ) SELECT kind||':'||key, value::text FROM rows ORDER BY kind COLLATE "C",key COLLATE "C"
$function$;
$definition$;
EXECUTE $definition$
CREATE OR REPLACE FUNCTION aegaeon.subject_history_observed_physical() RETURNS jsonb
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp
AS $function$
SELECT pg_catalog.jsonb_build_object(
'columns',(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('relation',c.relname,'name',a.attname,'type',pg_catalog.format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull,'collation',co.collname,'default',pg_catalog.pg_get_expr(d.adbin,d.adrelid)) ORDER BY c.relname COLLATE "C",a.attnum) FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_catalog.pg_collation co ON co.oid=a.attcollation LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE n.nspname='aegaeon' AND c.relname IN ('subject_ownership_namespaces','subject_ownership_adoptions','end_user_identity_owners','end_user_subject_reservations','end_users','end_user_password_credentials','end_user_profiles','user_attribute_sources','lti_registrations','lti_registration_revisions','lti_identifiers','lti_launch_intents','environments','authorization_domains','authorization_domain_targets','application_organizations','organization_role_definitions','organization_memberships','organization_authority_events','organization_authority_outbox','organization_authority_receipts','organization_operator_grants','organization_client_bindings','organization_invitations','organization_invitation_challenges','organization_identity_requests','organization_admin_access_grants','organization_import_operations','organization_creation_receipts','subject_history_restorations','subject_history_restoration_pages') AND a.attnum>0 AND NOT a.attisdropped),
'constraints',(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('relation',c.relname,'name',con.conname,'definition',pg_catalog.pg_get_constraintdef(con.oid,false),'validated',con.convalidated,'deferrable',con.condeferrable,'deferred',con.condeferred) ORDER BY c.relname COLLATE "C",con.conname COLLATE "C") FROM pg_catalog.pg_constraint con JOIN pg_catalog.pg_class c ON c.oid=con.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='aegaeon' AND c.relname IN ('subject_ownership_namespaces','subject_ownership_adoptions','end_user_identity_owners','end_user_subject_reservations','end_users','end_user_password_credentials','end_user_profiles','user_attribute_sources','lti_registrations','lti_registration_revisions','lti_identifiers','lti_launch_intents','environments','authorization_domains','authorization_domain_targets','application_organizations','organization_role_definitions','organization_memberships','organization_authority_events','organization_authority_outbox','organization_authority_receipts','organization_operator_grants','organization_client_bindings','organization_invitations','organization_invitation_challenges','organization_identity_requests','organization_admin_access_grants','organization_import_operations','organization_creation_receipts','subject_history_restorations','subject_history_restoration_pages')),
'triggers',(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('relation',c.relname,'name',t.tgname,'type',t.tgtype,'function',p.proname,'enabled',t.tgenabled,'arguments',pg_catalog.encode(t.tgargs,'hex'),'qualifier',pg_catalog.pg_get_expr(t.tgqual,t.tgrelid),'function_sha256',pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.pg_get_functiondef(p.oid),'UTF8')),'hex')) ORDER BY c.relname COLLATE "C",t.tgname COLLATE "C") FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid WHERE n.nspname='aegaeon' AND c.relname IN ('subject_ownership_namespaces','subject_ownership_adoptions','end_user_identity_owners','end_user_subject_reservations','end_users','end_user_password_credentials','end_user_profiles','user_attribute_sources','lti_registrations','lti_registration_revisions','lti_identifiers','lti_launch_intents','environments','authorization_domains','authorization_domain_targets','application_organizations','organization_role_definitions','organization_memberships','organization_authority_events','organization_authority_outbox','organization_authority_receipts','organization_operator_grants','organization_client_bindings','organization_invitations','organization_invitation_challenges','organization_identity_requests','organization_admin_access_grants','organization_import_operations','organization_creation_receipts','subject_history_restorations','subject_history_restoration_pages') AND NOT t.tgisinternal),
'indexes',(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('relation',c.relname,'name',ic.relname,'definition',pg_catalog.pg_get_indexdef(i.indexrelid),'unique',i.indisunique,'valid',i.indisvalid,'ready',i.indisready,'live',i.indislive,'immediate',i.indimmediate) ORDER BY c.relname COLLATE "C",ic.relname COLLATE "C") FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_class ic ON ic.oid=i.indexrelid WHERE n.nspname='aegaeon' AND c.relname IN ('authorization_domains','authorization_domain_targets','application_organizations','organization_role_definitions','organization_memberships','organization_authority_events','organization_authority_outbox','organization_authority_receipts','organization_operator_grants','organization_client_bindings','organization_invitations','organization_invitation_challenges','organization_identity_requests','organization_admin_access_grants','organization_import_operations','organization_creation_receipts','subject_history_restorations','subject_history_restoration_pages','user_attribute_sources','lti_registrations','lti_registration_revisions','lti_identifiers','lti_launch_intents'))
);
$function$;
$definition$;
EXECUTE $definition$
CREATE OR REPLACE FUNCTION aegaeon.subject_history_check_runtime_role(runtime_name text) RETURNS void
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE runtime_id oid; entry_id oid; reachable record; role_row record; relation_row record; schema_owner oid;
BEGIN
  SELECT * INTO role_row FROM pg_catalog.pg_roles WHERE rolname = runtime_name;
  IF NOT FOUND OR NOT role_row.rolcanlogin OR role_row.rolsuper OR role_row.rolcreatedb
     OR role_row.rolcreaterole OR role_row.rolreplication OR role_row.rolbypassrls THEN
    RAISE EXCEPTION 'subject runtime role is not a restricted login';
  END IF;
  entry_id := role_row.oid;
  IF pg_catalog.pg_has_role(entry_id,'aegaeon_subject_owner','MEMBER')
     OR pg_catalog.pg_has_role(entry_id,'aegaeon_subject_maintenance','MEMBER') THEN
    RAISE EXCEPTION 'subject runtime has protected group membership, including administrative authority';
  END IF;
  FOR reachable IN SELECT oid FROM pg_catalog.pg_roles r WHERE pg_catalog.pg_has_role(entry_id,r.oid,'USAGE') OR pg_catalog.pg_has_role(entry_id,r.oid,'SET') LOOP
  runtime_id := reachable.oid;
  FOR relation_row IN SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='aegaeon' AND c.relname IN ('subject_history_restorations','subject_history_restoration_pages') LOOP
    IF pg_catalog.has_table_privilege(runtime_id,relation_row.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
      OR pg_catalog.has_any_column_privilege(runtime_id,relation_row.oid,'SELECT,INSERT,UPDATE,REFERENCES') THEN
      RAISE EXCEPTION 'runtime has direct history restoration authority';
    END IF;
  END LOOP;
  IF pg_catalog.has_table_privilege(runtime_id,'aegaeon.organization_creation_receipts','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
    OR pg_catalog.has_any_column_privilege(runtime_id,'aegaeon.organization_creation_receipts','INSERT,UPDATE,REFERENCES') THEN
    RAISE EXCEPTION 'runtime has direct creation receipt mutation authority';
  END IF;

  IF pg_catalog.has_schema_privilege(runtime_id, 'aegaeon', 'CREATE')
     OR pg_catalog.has_parameter_privilege(runtime_id, 'session_replication_role', 'SET') THEN
    RAISE EXCEPTION 'subject runtime can bypass protected schema guards';
  END IF;
  SELECT nspowner INTO schema_owner FROM pg_catalog.pg_namespace WHERE nspname = 'aegaeon';
  IF pg_catalog.pg_has_role(runtime_id, schema_owner, 'USAGE') OR pg_catalog.pg_has_role(runtime_id, schema_owner, 'SET') THEN
    RAISE EXCEPTION 'subject runtime can assume schema ownership';
  END IF;
  FOR role_row IN SELECT * FROM pg_catalog.pg_roles
      WHERE rolname IN ('aegaeon_subject_owner', 'aegaeon_subject_maintenance')
         OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls LOOP
    IF pg_catalog.pg_has_role(runtime_id, role_row.oid, 'USAGE') OR pg_catalog.pg_has_role(runtime_id, role_row.oid, 'SET') THEN
      RAISE EXCEPTION 'subject runtime can assume protected or administrative authority';
    END IF;
  END LOOP;
  FOR relation_row IN SELECT c.oid, c.relname, c.relowner FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      WHERE (n.nspname = 'aegaeon' AND c.relname IN ('environments', 'end_users','end_user_password_credentials','end_user_profiles','user_attribute_sources','lti_registrations','lti_registration_revisions','lti_identifiers','lti_launch_intents',
        'subject_ownership_namespaces', 'subject_ownership_adoptions',
        'end_user_identity_owners', 'end_user_subject_reservations','authorization_domains','authorization_domain_targets','application_organizations','organization_role_definitions','organization_memberships','organization_authority_events','organization_authority_outbox','organization_authority_receipts','organization_operator_grants','organization_client_bindings','organization_invitations','organization_invitation_challenges','organization_identity_requests','organization_admin_access_grants','organization_import_operations','organization_creation_receipts','subject_history_restorations','subject_history_restoration_pages'))
        OR (c.relname='atlas_schema_revisions' AND n.nspname IN ('public','aegaeon')) LOOP
    IF pg_catalog.pg_has_role(runtime_id, relation_row.relowner, 'USAGE')
       OR pg_catalog.pg_has_role(runtime_id, relation_row.relowner, 'SET') THEN
      RAISE EXCEPTION 'subject runtime can assume ownership of a guarded table';
    END IF;
    IF pg_catalog.has_table_privilege(runtime_id, relation_row.oid, 'TRIGGER') THEN
      RAISE EXCEPTION 'subject runtime can install competing identity triggers';
    END IF;
    IF relation_row.relname NOT IN ('environments', 'end_users','end_user_password_credentials','end_user_profiles','user_attribute_sources','lti_registrations','lti_registration_revisions','lti_identifiers','lti_launch_intents','authorization_domains','authorization_domain_targets','application_organizations','organization_role_definitions','organization_memberships','organization_authority_events','organization_authority_outbox','organization_authority_receipts','organization_operator_grants','organization_client_bindings','organization_invitations','organization_invitation_challenges','organization_identity_requests','organization_admin_access_grants','organization_import_operations','organization_creation_receipts')
       AND (pg_catalog.has_table_privilege(runtime_id, relation_row.oid, 'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
         OR pg_catalog.has_any_column_privilege(runtime_id, relation_row.oid, 'INSERT,UPDATE')) THEN
      RAISE EXCEPTION 'subject runtime has permanent authority mutation privileges';
    END IF;
  END LOOP;
  -- Relation OIDs include the parent, leaves and subpartitions in every schema.
  -- INSERT and SELECT are legitimate runtime audit operations; mutation is not.
  FOR relation_row IN SELECT c.oid,c.relowner
      FROM pg_catalog.pg_partition_tree('aegaeon.audit_events'::regclass) t
      JOIN pg_catalog.pg_class c ON c.oid=t.relid LOOP
    IF pg_catalog.pg_has_role(runtime_id,relation_row.relowner,'USAGE')
       OR pg_catalog.pg_has_role(runtime_id,relation_row.relowner,'SET')
       OR pg_catalog.has_table_privilege(runtime_id,relation_row.oid,'UPDATE,DELETE,TRUNCATE,TRIGGER')
       OR pg_catalog.has_any_column_privilege(runtime_id,relation_row.oid,'UPDATE') THEN
      RAISE EXCEPTION 'subject runtime can rewrite protected audit history';
    END IF;
  END LOOP;
  IF EXISTS (SELECT FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname='aegaeon'
      AND (p.proname LIKE 'subject_history_%' OR p.proname IN
        ('organization_import_hold_guard','organization_identity_guard','organization_identity_credential_guard','organization_identity_policy_guard','organization_identity_profile_guard','organization_support_policy_guard','organization_admin_access_guard','subject_ownership_guard_user','subject_ownership_guard_environment','subject_ownership_immutable','subject_ownership_guard_insert',
         'inventory_subject_ownership_history_v1','adopt_subject_ownership_history_v1'))
      AND (pg_catalog.has_function_privilege(runtime_id, p.oid, 'EXECUTE')
        OR pg_catalog.pg_has_role(runtime_id,p.proowner,'USAGE') OR pg_catalog.pg_has_role(runtime_id,p.proowner,'SET'))) THEN
    RAISE EXCEPTION 'subject runtime can execute or own protected maintenance helpers';
  END IF;
  IF pg_catalog.has_table_privilege(runtime_id,'aegaeon.organization_identity_requests','UPDATE')
    OR EXISTS (SELECT FROM pg_catalog.pg_attribute a WHERE a.attrelid='aegaeon.organization_identity_requests'::regclass
      AND a.attnum>0 AND NOT a.attisdropped
      AND a.attname NOT IN ('state','result','delivery_revision','delivered_at','delivery_outcome','capability_hash')
      AND pg_catalog.has_column_privilege(runtime_id,a.attrelid,a.attnum,'UPDATE')) THEN
    RAISE EXCEPTION 'runtime can rewrite identity request bindings';
  END IF;
  -- History deletion and identity replacement are not runtime operations.
  FOR relation_row IN SELECT c.oid,c.relname FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='aegaeon' AND c.relname IN ('authorization_domains','authorization_domain_targets','application_organizations','organization_role_definitions','organization_memberships','organization_authority_events','organization_authority_outbox','organization_authority_receipts','organization_operator_grants','organization_client_bindings','organization_invitations','organization_invitation_challenges','organization_identity_requests','organization_admin_access_grants','organization_import_operations','organization_creation_receipts','subject_history_restorations','subject_history_restoration_pages') LOOP
    IF pg_catalog.has_table_privilege(runtime_id,relation_row.oid,'DELETE,TRUNCATE,REFERENCES')
       OR pg_catalog.has_any_column_privilege(runtime_id,relation_row.oid,'REFERENCES') THEN
      RAISE EXCEPTION 'organization runtime can delete or redefine authority history';
    END IF;
    IF EXISTS (SELECT FROM pg_catalog.pg_attribute a WHERE a.attrelid=relation_row.oid
        AND a.attnum>0 AND NOT a.attisdropped
        AND a.attname<>ALL(CASE relation_row.relname
        WHEN 'organization_invitations' THEN ARRAY['state','revision','delivery_revision','delivered_at','capability_hash','accepted_challenge_id','result','delivery_outcome']::text[]
        WHEN 'organization_invitation_challenges' THEN ARRAY['delivery_revision','delivered_at','capability_hash','delivery_outcome']::text[]
        WHEN 'organization_identity_requests' THEN ARRAY['state','result','delivery_revision','delivered_at','capability_hash','delivery_outcome']::text[]
        WHEN 'organization_client_bindings' THEN ARRAY['active','revision','targets']::text[]
        WHEN 'organization_operator_grants' THEN ARRAY['active','revision','capabilities']::text[]
        WHEN 'organization_admin_access_grants' THEN ARRAY['active','revision','revocation_key','revocation_digest']::text[]
        WHEN 'authorization_domains' THEN ARRAY['name','is_default','enabled','revision','invitation_delivery','support_policy','support_policy_revision']::text[]
        WHEN 'authorization_domain_targets' THEN ARRAY['domain_id','management','introspection_clients']::text[]
        WHEN 'application_organizations' THEN ARRAY['state','revision','grant_generation']::text[]
        WHEN 'organization_role_definitions' THEN ARRAY['version','privileges','manages_members','assignable_roles']::text[]
        WHEN 'organization_memberships' THEN ARRAY['state','revision','grant_generation','roles']::text[]
        WHEN 'organization_authority_outbox' THEN ARRAY['delivered_at','attempts']::text[]
        ELSE ARRAY[]::text[] END)
        AND pg_catalog.has_column_privilege(runtime_id,relation_row.oid,a.attnum,'UPDATE')) THEN
      RAISE EXCEPTION 'organization runtime can replace identity or rewrite immutable records';
    END IF;
  END LOOP;
  END LOOP;
END
$function$;
$definition$;
EXECUTE $definition$
CREATE OR REPLACE FUNCTION aegaeon.subject_history_check_maintenance_role(actor_name text) RETURNS void
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE actor_oid oid; reachable record; relation_row record;
BEGIN
    SELECT oid INTO actor_oid FROM pg_catalog.pg_roles WHERE rolname=actor_name;
    IF actor_oid IS NULL OR pg_catalog.pg_has_role(actor_oid,'aegaeon_subject_owner','MEMBER') THEN
      RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='maintenance actor has ownership membership, including administrative authority';
    END IF;
    FOR reachable IN SELECT * FROM pg_catalog.pg_roles r WHERE pg_catalog.pg_has_role(actor_oid,r.oid,'USAGE') OR pg_catalog.pg_has_role(actor_oid,r.oid,'SET') LOOP
      IF reachable.rolsuper OR reachable.rolcreatedb OR reachable.rolcreaterole OR reachable.rolreplication OR reachable.rolbypassrls
        OR reachable.rolname='aegaeon_subject_owner'
        OR pg_catalog.has_schema_privilege(reachable.oid,'aegaeon','CREATE')
        OR pg_catalog.has_parameter_privilege(reachable.oid,'session_replication_role','SET') THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='maintenance actor can bypass protected authority';
      END IF;
      FOR relation_row IN SELECT c.oid,c.relowner FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE (n.nspname='aegaeon' AND c.relname IN ('environments','end_users','end_user_password_credentials','end_user_profiles','user_attribute_sources','lti_registrations','lti_registration_revisions','lti_identifiers','lti_launch_intents','tenants','subject_ownership_namespaces','subject_ownership_adoptions','end_user_identity_owners','end_user_subject_reservations','authorization_domains','authorization_domain_targets','application_organizations','organization_role_definitions','organization_memberships','organization_authority_events','organization_authority_outbox','organization_authority_receipts','organization_operator_grants','organization_client_bindings','organization_invitations','organization_invitation_challenges','organization_identity_requests','organization_admin_access_grants','organization_import_operations','organization_creation_receipts','subject_history_restorations','subject_history_restoration_pages'))
          OR c.oid IN (SELECT relid FROM pg_catalog.pg_partition_tree('aegaeon.audit_events'::regclass))
          OR (c.relname='atlas_schema_revisions' AND n.nspname IN ('public','aegaeon')) LOOP
        IF reachable.oid=relation_row.relowner OR pg_catalog.has_table_privilege(reachable.oid,relation_row.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
          OR pg_catalog.has_any_column_privilege(reachable.oid,relation_row.oid,'SELECT,INSERT,UPDATE,REFERENCES') THEN
          RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='maintenance actor requires EXECUTE-only source authority';
        END IF;
      END LOOP;
      IF EXISTS (SELECT FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
          WHERE n.nspname='aegaeon' AND (p.proname LIKE 'subject_history_%' OR p.proname IN
            ('organization_creation_record_v1','organization_import_hold_guard','organization_identity_guard','organization_identity_credential_guard','organization_identity_policy_guard','organization_identity_profile_guard','organization_support_policy_guard','organization_admin_access_guard','organization_snapshot_history_v1','subject_ownership_guard_user','subject_ownership_guard_environment','subject_ownership_immutable','subject_ownership_guard_insert'))
          AND (pg_catalog.has_function_privilege(reachable.oid,p.oid,'EXECUTE')
            OR pg_catalog.pg_has_role(reachable.oid,p.proowner,'USAGE') OR pg_catalog.pg_has_role(reachable.oid,p.proowner,'SET'))) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='maintenance actor can execute private authority helpers';
      END IF;
    END LOOP;
END
$function$;
$definition$;
EXECUTE $definition$
CREATE OR REPLACE FUNCTION aegaeon.subject_history_lock() RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE partition_row record;
BEGIN
  PERFORM pg_catalog.pg_advisory_xact_lock(1095059265, 1398096433);
  LOCK TABLE aegaeon.environments IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.subject_ownership_namespaces IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.subject_ownership_adoptions IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.end_user_identity_owners IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.end_user_subject_reservations IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.end_users IN SHARE ROW EXCLUSIVE MODE;
  -- Parent ACCESS EXCLUSIVE excludes DML and ATTACH/DETACH before enumeration.
  LOCK TABLE ONLY aegaeon.audit_events IN ACCESS EXCLUSIVE MODE;
  FOR partition_row IN SELECT c.oid, n.nspname, c.relname
      FROM pg_catalog.pg_partition_tree('aegaeon.audit_events'::regclass) t
      JOIN pg_catalog.pg_class c ON c.oid=t.relid
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE t.level > 0 ORDER BY c.oid LOOP
    -- Identifiers originate only in the locked physical catalog, never manifest input.
    EXECUTE pg_catalog.format('LOCK TABLE ONLY %I.%I IN ACCESS EXCLUSIVE MODE', partition_row.nspname, partition_row.relname);
  END LOOP;
  LOCK TABLE aegaeon.authorization_domains IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.organization_operator_grants IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.organization_client_bindings IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.organization_invitations IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.organization_invitation_challenges IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.authorization_domain_targets IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.application_organizations IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.organization_role_definitions IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.organization_memberships IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.organization_authority_events IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.organization_authority_outbox IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.organization_authority_receipts IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.organization_creation_receipts IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.subject_history_restorations IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.subject_history_restoration_pages IN SHARE ROW EXCLUSIVE MODE;
  PERFORM aegaeon.subject_history_lock_revisions();
END
$function$;
$definition$;
EXECUTE $definition$
CREATE OR REPLACE FUNCTION aegaeon.subject_history_preflight(runtime_name text) RETURNS text
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE expected jsonb := $physical${"columns":[{"name":"id","type":"uuid","default":null,"not_null":true,"relation":"application_organizations","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"application_organizations","collation":null},{"name":"domain_id","type":"uuid","default":null,"not_null":true,"relation":"application_organizations","collation":null},{"name":"external_id","type":"text","default":null,"not_null":true,"relation":"application_organizations","collation":"C"},{"name":"state","type":"text","default":null,"not_null":true,"relation":"application_organizations","collation":"default"},{"name":"revision","type":"bigint","default":"1","not_null":true,"relation":"application_organizations","collation":null},{"name":"grant_generation","type":"bigint","default":"1","not_null":true,"relation":"application_organizations","collation":null},{"name":"created_at","type":"timestamp with time zone","default":"statement_timestamp()","not_null":true,"relation":"application_organizations","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"authorization_domain_targets","collation":null},{"name":"domain_id","type":"uuid","default":null,"not_null":true,"relation":"authorization_domain_targets","collation":null},{"name":"audience","type":"text","default":null,"not_null":true,"relation":"authorization_domain_targets","collation":"C"},{"name":"management","type":"boolean","default":"false","not_null":true,"relation":"authorization_domain_targets","collation":null},{"name":"introspection_clients","type":"jsonb","default":"'[]'::jsonb","not_null":true,"relation":"authorization_domain_targets","collation":null},{"name":"id","type":"uuid","default":null,"not_null":true,"relation":"authorization_domains","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"authorization_domains","collation":null},{"name":"name","type":"text","default":null,"not_null":true,"relation":"authorization_domains","collation":"default"},{"name":"is_default","type":"boolean","default":"false","not_null":true,"relation":"authorization_domains","collation":null},{"name":"enabled","type":"boolean","default":"false","not_null":true,"relation":"authorization_domains","collation":null},{"name":"revision","type":"bigint","default":"1","not_null":true,"relation":"authorization_domains","collation":null},{"name":"invitation_delivery","type":"jsonb","default":null,"not_null":false,"relation":"authorization_domains","collation":null},{"name":"support_policy","type":"jsonb","default":null,"not_null":false,"relation":"authorization_domains","collation":null},{"name":"support_policy_revision","type":"bigint","default":"1","not_null":true,"relation":"authorization_domains","collation":null},{"name":"import_operation_id","type":"uuid","default":null,"not_null":false,"relation":"authorization_domains","collation":null},{"name":"owner_id","type":"uuid","default":null,"not_null":true,"relation":"end_user_identity_owners","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"end_user_identity_owners","collation":null},{"name":"recorded_at","type":"timestamp with time zone","default":"clock_timestamp()","not_null":true,"relation":"end_user_identity_owners","collation":null},{"name":"id","type":"uuid","default":"gen_random_uuid()","not_null":true,"relation":"end_user_password_credentials","collation":null},{"name":"end_user_id","type":"uuid","default":null,"not_null":true,"relation":"end_user_password_credentials","collation":null},{"name":"password_hash","type":"text","default":null,"not_null":true,"relation":"end_user_password_credentials","collation":"default"},{"name":"status","type":"aegaeon.end_user_password_credential_status","default":"'ACTIVE'::aegaeon.end_user_password_credential_status","not_null":true,"relation":"end_user_password_credentials","collation":null},{"name":"created_at","type":"timestamp with time zone","default":"now()","not_null":true,"relation":"end_user_password_credentials","collation":null},{"name":"updated_at","type":"timestamp with time zone","default":"now()","not_null":true,"relation":"end_user_password_credentials","collation":null},{"name":"last_used_at","type":"timestamp with time zone","default":null,"not_null":false,"relation":"end_user_password_credentials","collation":null},{"name":"created_by_administrator_id","type":"uuid","default":null,"not_null":false,"relation":"end_user_password_credentials","collation":null},{"name":"revoked_by_administrator_id","type":"uuid","default":null,"not_null":false,"relation":"end_user_password_credentials","collation":null},{"name":"end_user_id","type":"uuid","default":null,"not_null":true,"relation":"end_user_profiles","collation":null},{"name":"subject_policy","type":"text","default":"'explicit'::text","not_null":true,"relation":"end_user_profiles","collation":"default"},{"name":"email_verified","type":"boolean","default":"false","not_null":true,"relation":"end_user_profiles","collation":null},{"name":"display_name","type":"text","default":null,"not_null":false,"relation":"end_user_profiles","collation":"default"},{"name":"custom_claims","type":"jsonb","default":"'{}'::jsonb","not_null":true,"relation":"end_user_profiles","collation":null},{"name":"profile_version","type":"bigint","default":"1","not_null":true,"relation":"end_user_profiles","collation":null},{"name":"created_at","type":"timestamp with time zone","default":"now()","not_null":true,"relation":"end_user_profiles","collation":null},{"name":"updated_at","type":"timestamp with time zone","default":"now()","not_null":true,"relation":"end_user_profiles","collation":null},{"name":"verified_delivery_address","type":"text","default":null,"not_null":false,"relation":"end_user_profiles","collation":"C"},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"end_user_subject_reservations","collation":null},{"name":"subject","type":"text","default":null,"not_null":true,"relation":"end_user_subject_reservations","collation":"C"},{"name":"owner_id","type":"uuid","default":null,"not_null":true,"relation":"end_user_subject_reservations","collation":null},{"name":"recorded_at","type":"timestamp with time zone","default":"clock_timestamp()","not_null":true,"relation":"end_user_subject_reservations","collation":null},{"name":"id","type":"uuid","default":"gen_random_uuid()","not_null":true,"relation":"end_users","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"end_users","collation":null},{"name":"subject","type":"text","default":null,"not_null":true,"relation":"end_users","collation":"C"},{"name":"email","type":"text","default":null,"not_null":false,"relation":"end_users","collation":"default"},{"name":"status","type":"aegaeon.end_user_status","default":"'INVITED'::aegaeon.end_user_status","not_null":true,"relation":"end_users","collation":null},{"name":"blocked_at","type":"timestamp with time zone","default":null,"not_null":false,"relation":"end_users","collation":null},{"name":"blocked_reason","type":"text","default":null,"not_null":false,"relation":"end_users","collation":"default"},{"name":"created_at","type":"timestamp with time zone","default":"now()","not_null":true,"relation":"end_users","collation":null},{"name":"updated_at","type":"timestamp with time zone","default":"now()","not_null":true,"relation":"end_users","collation":null},{"name":"organization_identity_revision","type":"bigint","default":"1","not_null":true,"relation":"end_users","collation":null},{"name":"organization_reauthentication_after","type":"bigint","default":"0","not_null":true,"relation":"end_users","collation":null},{"name":"id","type":"uuid","default":"gen_random_uuid()","not_null":true,"relation":"environments","collation":null},{"name":"tenant_id","type":"uuid","default":null,"not_null":true,"relation":"environments","collation":null},{"name":"name","type":"text","default":null,"not_null":true,"relation":"environments","collation":"default"},{"name":"slug","type":"text","default":null,"not_null":true,"relation":"environments","collation":"default"},{"name":"issuer_host","type":"text","default":null,"not_null":true,"relation":"environments","collation":"default"},{"name":"issuer_url","type":"text","default":"('https://'::text || issuer_host)","not_null":false,"relation":"environments","collation":"default"},{"name":"active_configuration_version_id","type":"uuid","default":null,"not_null":false,"relation":"environments","collation":null},{"name":"status","type":"aegaeon.environment_status","default":"'ACTIVE'::aegaeon.environment_status","not_null":true,"relation":"environments","collation":null},{"name":"created_at","type":"timestamp with time zone","default":"now()","not_null":true,"relation":"environments","collation":null},{"name":"updated_at","type":"timestamp with time zone","default":"now()","not_null":true,"relation":"environments","collation":null},{"name":"deleted_at","type":"timestamp with time zone","default":null,"not_null":false,"relation":"environments","collation":null},{"name":"organization_identity_policy","type":"jsonb","default":null,"not_null":false,"relation":"environments","collation":null},{"name":"organization_identity_policy_revision","type":"bigint","default":"1","not_null":true,"relation":"environments","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"lti_identifiers","collation":null},{"name":"kind","type":"text","default":null,"not_null":true,"relation":"lti_identifiers","collation":"default"},{"name":"identifier","type":"text","default":null,"not_null":true,"relation":"lti_identifiers","collation":"C"},{"name":"registration_id","type":"uuid","default":null,"not_null":true,"relation":"lti_identifiers","collation":null},{"name":"deployment_id","type":"text","default":null,"not_null":true,"relation":"lti_identifiers","collation":"C"},{"name":"context_id","type":"text","default":null,"not_null":false,"relation":"lti_identifiers","collation":"C"},{"name":"id","type":"uuid","default":"gen_random_uuid()","not_null":true,"relation":"lti_launch_intents","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"lti_launch_intents","collation":null},{"name":"registration_id","type":"uuid","default":null,"not_null":true,"relation":"lti_launch_intents","collation":null},{"name":"revision","type":"bigint","default":null,"not_null":true,"relation":"lti_launch_intents","collation":null},{"name":"runtime_revision","type":"uuid","default":null,"not_null":true,"relation":"lti_launch_intents","collation":null},{"name":"runtime_fingerprint","type":"text","default":null,"not_null":true,"relation":"lti_launch_intents","collation":"default"},{"name":"owner_id","type":"uuid","default":null,"not_null":true,"relation":"lti_launch_intents","collation":null},{"name":"subject","type":"text","default":null,"not_null":true,"relation":"lti_launch_intents","collation":"C"},{"name":"producer_client_id","type":"text","default":null,"not_null":true,"relation":"lti_launch_intents","collation":"default"},{"name":"producer_token_digest","type":"text","default":null,"not_null":true,"relation":"lti_launch_intents","collation":"default"},{"name":"producer_metadata","type":"jsonb","default":null,"not_null":true,"relation":"lti_launch_intents","collation":null},{"name":"deployment_id","type":"text","default":null,"not_null":true,"relation":"lti_launch_intents","collation":"C"},{"name":"resource_link_id","type":"text","default":null,"not_null":true,"relation":"lti_launch_intents","collation":"C"},{"name":"roles","type":"jsonb","default":null,"not_null":true,"relation":"lti_launch_intents","collation":null},{"name":"ticket_hash","type":"text","default":null,"not_null":true,"relation":"lti_launch_intents","collation":"default"},{"name":"login_hint_hash","type":"text","default":null,"not_null":false,"relation":"lti_launch_intents","collation":"default"},{"name":"message_hint_hash","type":"text","default":null,"not_null":false,"relation":"lti_launch_intents","collation":"default"},{"name":"session_hash","type":"text","default":null,"not_null":false,"relation":"lti_launch_intents","collation":"default"},{"name":"csrf_hash","type":"text","default":null,"not_null":false,"relation":"lti_launch_intents","collation":"default"},{"name":"continuation_hash","type":"text","default":null,"not_null":false,"relation":"lti_launch_intents","collation":"default"},{"name":"authorization_request","type":"jsonb","default":null,"not_null":false,"relation":"lti_launch_intents","collation":null},{"name":"status","type":"text","default":"'pending'::text","not_null":true,"relation":"lti_launch_intents","collation":"default"},{"name":"created_at","type":"bigint","default":null,"not_null":true,"relation":"lti_launch_intents","collation":null},{"name":"expires_at","type":"bigint","default":null,"not_null":true,"relation":"lti_launch_intents","collation":null},{"name":"consumed_at","type":"bigint","default":null,"not_null":false,"relation":"lti_launch_intents","collation":null},{"name":"response_digest","type":"text","default":null,"not_null":false,"relation":"lti_launch_intents","collation":"default"},{"name":"registration_id","type":"uuid","default":null,"not_null":true,"relation":"lti_registration_revisions","collation":null},{"name":"revision","type":"bigint","default":null,"not_null":true,"relation":"lti_registration_revisions","collation":null},{"name":"document","type":"jsonb","default":null,"not_null":true,"relation":"lti_registration_revisions","collation":null},{"name":"author_id","type":"uuid","default":null,"not_null":true,"relation":"lti_registration_revisions","collation":null},{"name":"created_at","type":"timestamp with time zone","default":"clock_timestamp()","not_null":true,"relation":"lti_registration_revisions","collation":null},{"name":"id","type":"uuid","default":"gen_random_uuid()","not_null":true,"relation":"lti_registrations","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"lti_registrations","collation":null},{"name":"client_record_id","type":"uuid","default":null,"not_null":true,"relation":"lti_registrations","collation":null},{"name":"client_id","type":"text","default":null,"not_null":true,"relation":"lti_registrations","collation":"default"},{"name":"revision","type":"bigint","default":"0","not_null":true,"relation":"lti_registrations","collation":null},{"name":"active_revision","type":"bigint","default":null,"not_null":false,"relation":"lti_registrations","collation":null},{"name":"id","type":"uuid","default":null,"not_null":true,"relation":"organization_admin_access_grants","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"organization_admin_access_grants","collation":null},{"name":"domain_id","type":"uuid","default":null,"not_null":true,"relation":"organization_admin_access_grants","collation":null},{"name":"organization_id","type":"uuid","default":null,"not_null":true,"relation":"organization_admin_access_grants","collation":null},{"name":"user_id","type":"uuid","default":null,"not_null":true,"relation":"organization_admin_access_grants","collation":null},{"name":"client_registration_id","type":"uuid","default":null,"not_null":true,"relation":"organization_admin_access_grants","collation":null},{"name":"root_id","type":"text","default":null,"not_null":true,"relation":"organization_admin_access_grants","collation":"C"},{"name":"authority","type":"jsonb","default":null,"not_null":true,"relation":"organization_admin_access_grants","collation":null},{"name":"revision","type":"bigint","default":"1","not_null":true,"relation":"organization_admin_access_grants","collation":null},{"name":"active","type":"boolean","default":"true","not_null":true,"relation":"organization_admin_access_grants","collation":null},{"name":"issued_at","type":"bigint","default":null,"not_null":true,"relation":"organization_admin_access_grants","collation":null},{"name":"expires_at","type":"bigint","default":null,"not_null":true,"relation":"organization_admin_access_grants","collation":null},{"name":"creation_key","type":"text","default":null,"not_null":true,"relation":"organization_admin_access_grants","collation":"C"},{"name":"request_digest","type":"bytea","default":null,"not_null":true,"relation":"organization_admin_access_grants","collation":null},{"name":"revocation_key","type":"text","default":null,"not_null":false,"relation":"organization_admin_access_grants","collation":"C"},{"name":"revocation_digest","type":"bytea","default":null,"not_null":false,"relation":"organization_admin_access_grants","collation":null},{"name":"id","type":"uuid","default":null,"not_null":true,"relation":"organization_authority_events","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"organization_authority_events","collation":null},{"name":"domain_id","type":"uuid","default":null,"not_null":true,"relation":"organization_authority_events","collation":null},{"name":"organization_id","type":"uuid","default":null,"not_null":false,"relation":"organization_authority_events","collation":null},{"name":"actor_id","type":"uuid","default":null,"not_null":true,"relation":"organization_authority_events","collation":null},{"name":"actor_kind","type":"text","default":null,"not_null":true,"relation":"organization_authority_events","collation":"default"},{"name":"client_id","type":"text","default":null,"not_null":true,"relation":"organization_authority_events","collation":"default"},{"name":"client_registration_id","type":"uuid","default":null,"not_null":false,"relation":"organization_authority_events","collation":null},{"name":"request_id","type":"text","default":null,"not_null":true,"relation":"organization_authority_events","collation":"default"},{"name":"reason","type":"text","default":null,"not_null":true,"relation":"organization_authority_events","collation":"default"},{"name":"event_type","type":"text","default":null,"not_null":true,"relation":"organization_authority_events","collation":"default"},{"name":"data","type":"jsonb","default":null,"not_null":true,"relation":"organization_authority_events","collation":null},{"name":"created_at","type":"timestamp with time zone","default":"statement_timestamp()","not_null":true,"relation":"organization_authority_events","collation":null},{"name":"event_id","type":"uuid","default":null,"not_null":true,"relation":"organization_authority_outbox","collation":null},{"name":"delivered_at","type":"timestamp with time zone","default":null,"not_null":false,"relation":"organization_authority_outbox","collation":null},{"name":"attempts","type":"bigint","default":"0","not_null":true,"relation":"organization_authority_outbox","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"organization_authority_receipts","collation":null},{"name":"domain_id","type":"uuid","default":null,"not_null":true,"relation":"organization_authority_receipts","collation":null},{"name":"actor_id","type":"uuid","default":null,"not_null":true,"relation":"organization_authority_receipts","collation":null},{"name":"actor_kind","type":"text","default":null,"not_null":true,"relation":"organization_authority_receipts","collation":"default"},{"name":"client_id","type":"text","default":null,"not_null":true,"relation":"organization_authority_receipts","collation":"default"},{"name":"client_registration_id","type":"uuid","default":null,"not_null":true,"relation":"organization_authority_receipts","collation":null},{"name":"operation","type":"text","default":null,"not_null":true,"relation":"organization_authority_receipts","collation":"default"},{"name":"idempotency_key","type":"text","default":null,"not_null":true,"relation":"organization_authority_receipts","collation":"C"},{"name":"request_digest","type":"bytea","default":null,"not_null":true,"relation":"organization_authority_receipts","collation":null},{"name":"result","type":"jsonb","default":null,"not_null":true,"relation":"organization_authority_receipts","collation":null},{"name":"created_at","type":"timestamp with time zone","default":"statement_timestamp()","not_null":true,"relation":"organization_authority_receipts","collation":null},{"name":"id","type":"uuid","default":null,"not_null":true,"relation":"organization_client_bindings","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"organization_client_bindings","collation":null},{"name":"domain_id","type":"uuid","default":null,"not_null":true,"relation":"organization_client_bindings","collation":null},{"name":"client_registration_id","type":"uuid","default":null,"not_null":true,"relation":"organization_client_bindings","collation":null},{"name":"client_identifier","type":"text","default":null,"not_null":true,"relation":"organization_client_bindings","collation":"C"},{"name":"active","type":"boolean","default":"false","not_null":true,"relation":"organization_client_bindings","collation":null},{"name":"revision","type":"bigint","default":"1","not_null":true,"relation":"organization_client_bindings","collation":null},{"name":"targets","type":"jsonb","default":null,"not_null":true,"relation":"organization_client_bindings","collation":null},{"name":"created_at","type":"timestamp with time zone","default":"statement_timestamp()","not_null":true,"relation":"organization_client_bindings","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"organization_creation_receipts","collation":null},{"name":"operation_id","type":"uuid","default":null,"not_null":true,"relation":"organization_creation_receipts","collation":null},{"name":"kind","type":"text","default":null,"not_null":true,"relation":"organization_creation_receipts","collation":"C"},{"name":"selector_sha256","type":"text","default":null,"not_null":true,"relation":"organization_creation_receipts","collation":"C"},{"name":"actor_sha256","type":"text","default":null,"not_null":true,"relation":"organization_creation_receipts","collation":"C"},{"name":"payload_sha256","type":"text","default":null,"not_null":true,"relation":"organization_creation_receipts","collation":"C"},{"name":"owner_id","type":"uuid","default":null,"not_null":true,"relation":"organization_creation_receipts","collation":null},{"name":"subject","type":"text","default":null,"not_null":true,"relation":"organization_creation_receipts","collation":"C"},{"name":"attempt","type":"integer","default":null,"not_null":true,"relation":"organization_creation_receipts","collation":null},{"name":"epoch","type":"uuid","default":null,"not_null":true,"relation":"organization_creation_receipts","collation":null},{"name":"identity_revision","type":"bigint","default":null,"not_null":true,"relation":"organization_creation_receipts","collation":null},{"name":"receipt_sha256","type":"bytea","default":null,"not_null":true,"relation":"organization_creation_receipts","collation":null},{"name":"recorded_at","type":"timestamp with time zone","default":"statement_timestamp()","not_null":true,"relation":"organization_creation_receipts","collation":null},{"name":"id","type":"uuid","default":null,"not_null":true,"relation":"organization_identity_requests","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"organization_identity_requests","collation":null},{"name":"domain_id","type":"uuid","default":null,"not_null":true,"relation":"organization_identity_requests","collation":null},{"name":"invitation_id","type":"uuid","default":null,"not_null":true,"relation":"organization_identity_requests","collation":null},{"name":"invitation_delivery_revision","type":"bigint","default":null,"not_null":true,"relation":"organization_identity_requests","collation":null},{"name":"policy_revision","type":"bigint","default":null,"not_null":true,"relation":"organization_identity_requests","collation":null},{"name":"purpose","type":"text","default":null,"not_null":true,"relation":"organization_identity_requests","collation":"default"},{"name":"request_key","type":"text","default":null,"not_null":true,"relation":"organization_identity_requests","collation":"C"},{"name":"request_digest","type":"bytea","default":null,"not_null":true,"relation":"organization_identity_requests","collation":null},{"name":"target_user_id","type":"uuid","default":null,"not_null":false,"relation":"organization_identity_requests","collation":null},{"name":"target_identity_revision","type":"bigint","default":null,"not_null":false,"relation":"organization_identity_requests","collation":null},{"name":"issued_at","type":"bigint","default":null,"not_null":true,"relation":"organization_identity_requests","collation":null},{"name":"expires_at","type":"bigint","default":null,"not_null":true,"relation":"organization_identity_requests","collation":null},{"name":"state","type":"text","default":"'pending'::text","not_null":true,"relation":"organization_identity_requests","collation":"default"},{"name":"result","type":"jsonb","default":null,"not_null":false,"relation":"organization_identity_requests","collation":null},{"name":"delivery_revision","type":"bigint","default":"0","not_null":true,"relation":"organization_identity_requests","collation":null},{"name":"delivered_at","type":"bigint","default":null,"not_null":false,"relation":"organization_identity_requests","collation":null},{"name":"delivery_outcome","type":"text","default":"'unclaimed'::text","not_null":true,"relation":"organization_identity_requests","collation":"default"},{"name":"capability_hash","type":"bytea","default":null,"not_null":false,"relation":"organization_identity_requests","collation":null},{"name":"id","type":"uuid","default":null,"not_null":true,"relation":"organization_import_operations","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"organization_import_operations","collation":null},{"name":"domain_id","type":"uuid","default":null,"not_null":true,"relation":"organization_import_operations","collation":null},{"name":"source_sha256","type":"text","default":null,"not_null":true,"relation":"organization_import_operations","collation":"C"},{"name":"source_enabled","type":"boolean","default":null,"not_null":true,"relation":"organization_import_operations","collation":null},{"name":"session_actor","type":"name","default":null,"not_null":true,"relation":"organization_import_operations","collation":"C"},{"name":"maintenance_actor","type":"name","default":null,"not_null":true,"relation":"organization_import_operations","collation":"C"},{"name":"state","type":"text","default":null,"not_null":true,"relation":"organization_import_operations","collation":"default"},{"name":"receipt","type":"jsonb","default":null,"not_null":true,"relation":"organization_import_operations","collation":null},{"name":"created_at","type":"timestamp with time zone","default":"statement_timestamp()","not_null":true,"relation":"organization_import_operations","collation":null},{"name":"id","type":"uuid","default":null,"not_null":true,"relation":"organization_invitation_challenges","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"organization_invitation_challenges","collation":null},{"name":"domain_id","type":"uuid","default":null,"not_null":true,"relation":"organization_invitation_challenges","collation":null},{"name":"invitation_id","type":"uuid","default":null,"not_null":true,"relation":"organization_invitation_challenges","collation":null},{"name":"invitation_delivery_revision","type":"bigint","default":null,"not_null":true,"relation":"organization_invitation_challenges","collation":null},{"name":"recipient_binding","type":"jsonb","default":null,"not_null":true,"relation":"organization_invitation_challenges","collation":null},{"name":"request_key","type":"text","default":null,"not_null":true,"relation":"organization_invitation_challenges","collation":"C"},{"name":"issued_at","type":"bigint","default":null,"not_null":true,"relation":"organization_invitation_challenges","collation":null},{"name":"expires_at","type":"bigint","default":null,"not_null":true,"relation":"organization_invitation_challenges","collation":null},{"name":"delivery_revision","type":"bigint","default":"0","not_null":true,"relation":"organization_invitation_challenges","collation":null},{"name":"delivered_at","type":"bigint","default":null,"not_null":false,"relation":"organization_invitation_challenges","collation":null},{"name":"capability_hash","type":"bytea","default":null,"not_null":false,"relation":"organization_invitation_challenges","collation":null},{"name":"delivery_outcome","type":"text","default":"'unclaimed'::text","not_null":true,"relation":"organization_invitation_challenges","collation":"default"},{"name":"id","type":"uuid","default":null,"not_null":true,"relation":"organization_invitations","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"organization_invitations","collation":null},{"name":"domain_id","type":"uuid","default":null,"not_null":true,"relation":"organization_invitations","collation":null},{"name":"organization_id","type":"uuid","default":null,"not_null":true,"relation":"organization_invitations","collation":null},{"name":"revision","type":"bigint","default":"1","not_null":true,"relation":"organization_invitations","collation":null},{"name":"state","type":"text","default":"'pending'::text","not_null":true,"relation":"organization_invitations","collation":"default"},{"name":"recipient","type":"text","default":null,"not_null":true,"relation":"organization_invitations","collation":"C"},{"name":"authority","type":"jsonb","default":null,"not_null":true,"relation":"organization_invitations","collation":null},{"name":"issued_at","type":"bigint","default":null,"not_null":true,"relation":"organization_invitations","collation":null},{"name":"expires_at","type":"bigint","default":null,"not_null":true,"relation":"organization_invitations","collation":null},{"name":"delivery_revision","type":"bigint","default":"0","not_null":true,"relation":"organization_invitations","collation":null},{"name":"delivered_at","type":"bigint","default":null,"not_null":false,"relation":"organization_invitations","collation":null},{"name":"capability_hash","type":"bytea","default":null,"not_null":false,"relation":"organization_invitations","collation":null},{"name":"accepted_challenge_id","type":"uuid","default":null,"not_null":false,"relation":"organization_invitations","collation":null},{"name":"result","type":"jsonb","default":null,"not_null":false,"relation":"organization_invitations","collation":null},{"name":"delivery_outcome","type":"text","default":"'unclaimed'::text","not_null":true,"relation":"organization_invitations","collation":"default"},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"organization_memberships","collation":null},{"name":"domain_id","type":"uuid","default":null,"not_null":true,"relation":"organization_memberships","collation":null},{"name":"organization_id","type":"uuid","default":null,"not_null":true,"relation":"organization_memberships","collation":null},{"name":"end_user_id","type":"uuid","default":null,"not_null":true,"relation":"organization_memberships","collation":null},{"name":"incarnation","type":"uuid","default":null,"not_null":true,"relation":"organization_memberships","collation":null},{"name":"state","type":"text","default":null,"not_null":true,"relation":"organization_memberships","collation":"default"},{"name":"revision","type":"bigint","default":"1","not_null":true,"relation":"organization_memberships","collation":null},{"name":"grant_generation","type":"bigint","default":"1","not_null":true,"relation":"organization_memberships","collation":null},{"name":"roles","type":"jsonb","default":null,"not_null":true,"relation":"organization_memberships","collation":null},{"name":"id","type":"uuid","default":null,"not_null":true,"relation":"organization_operator_grants","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"organization_operator_grants","collation":null},{"name":"domain_id","type":"uuid","default":null,"not_null":true,"relation":"organization_operator_grants","collation":null},{"name":"administrator_id","type":"uuid","default":null,"not_null":true,"relation":"organization_operator_grants","collation":null},{"name":"active","type":"boolean","default":"false","not_null":true,"relation":"organization_operator_grants","collation":null},{"name":"revision","type":"bigint","default":"1","not_null":true,"relation":"organization_operator_grants","collation":null},{"name":"capabilities","type":"jsonb","default":null,"not_null":true,"relation":"organization_operator_grants","collation":null},{"name":"created_at","type":"timestamp with time zone","default":"statement_timestamp()","not_null":true,"relation":"organization_operator_grants","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"organization_role_definitions","collation":null},{"name":"domain_id","type":"uuid","default":null,"not_null":true,"relation":"organization_role_definitions","collation":null},{"name":"role_key","type":"text","default":null,"not_null":true,"relation":"organization_role_definitions","collation":"C"},{"name":"version","type":"bigint","default":"1","not_null":true,"relation":"organization_role_definitions","collation":null},{"name":"privileges","type":"jsonb","default":null,"not_null":true,"relation":"organization_role_definitions","collation":null},{"name":"manages_members","type":"boolean","default":"false","not_null":true,"relation":"organization_role_definitions","collation":null},{"name":"assignable_roles","type":"jsonb","default":"'[]'::jsonb","not_null":true,"relation":"organization_role_definitions","collation":null},{"name":"operation_id","type":"uuid","default":null,"not_null":true,"relation":"subject_history_restoration_pages","collation":null},{"name":"after_sequence","type":"bigint","default":null,"not_null":true,"relation":"subject_history_restoration_pages","collation":null},{"name":"entry_count","type":"integer","default":null,"not_null":true,"relation":"subject_history_restoration_pages","collation":null},{"name":"digest","type":"bytea","default":null,"not_null":true,"relation":"subject_history_restoration_pages","collation":null},{"name":"input","type":"jsonb","default":null,"not_null":true,"relation":"subject_history_restoration_pages","collation":null},{"name":"recorded_at","type":"timestamp with time zone","default":"statement_timestamp()","not_null":true,"relation":"subject_history_restoration_pages","collation":null},{"name":"session_actor","type":"text","default":null,"not_null":true,"relation":"subject_history_restoration_pages","collation":"default"},{"name":"operation_id","type":"uuid","default":null,"not_null":true,"relation":"subject_history_restorations","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"subject_history_restorations","collation":null},{"name":"source","type":"jsonb","default":null,"not_null":true,"relation":"subject_history_restorations","collation":null},{"name":"recorded_at","type":"timestamp with time zone","default":"statement_timestamp()","not_null":true,"relation":"subject_history_restorations","collation":null},{"name":"session_actor","type":"text","default":null,"not_null":true,"relation":"subject_history_restorations","collation":"default"},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"subject_ownership_adoptions","collation":null},{"name":"kind","type":"text","default":null,"not_null":true,"relation":"subject_ownership_adoptions","collation":"default"},{"name":"receipt_id","type":"uuid","default":null,"not_null":true,"relation":"subject_ownership_adoptions","collation":null},{"name":"contract_version","type":"integer","default":"1","not_null":true,"relation":"subject_ownership_adoptions","collation":null},{"name":"recorded_at","type":"timestamp with time zone","default":"clock_timestamp()","not_null":true,"relation":"subject_ownership_adoptions","collation":null},{"name":"session_actor","type":"text","default":null,"not_null":true,"relation":"subject_ownership_adoptions","collation":"default"},{"name":"effective_actor","type":"text","default":null,"not_null":true,"relation":"subject_ownership_adoptions","collation":"default"},{"name":"definer_actor","type":"text","default":null,"not_null":true,"relation":"subject_ownership_adoptions","collation":"default"},{"name":"maintenance_reference","type":"text","default":null,"not_null":false,"relation":"subject_ownership_adoptions","collation":"default"},{"name":"manifest_sha256","type":"text","default":null,"not_null":false,"relation":"subject_ownership_adoptions","collation":"default"},{"name":"inventory_sha256","type":"text","default":null,"not_null":false,"relation":"subject_ownership_adoptions","collation":"default"},{"name":"receipt_data","type":"jsonb","default":null,"not_null":false,"relation":"subject_ownership_adoptions","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"subject_ownership_namespaces","collation":null},{"name":"issuer_host","type":"text","default":null,"not_null":true,"relation":"subject_ownership_namespaces","collation":"default"},{"name":"origin","type":"text","default":null,"not_null":true,"relation":"subject_ownership_namespaces","collation":"default"},{"name":"contract_version","type":"integer","default":"1","not_null":true,"relation":"subject_ownership_namespaces","collation":null},{"name":"recorded_at","type":"timestamp with time zone","default":"clock_timestamp()","not_null":true,"relation":"subject_ownership_namespaces","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"user_attribute_sources","collation":null},{"name":"end_user_id","type":"uuid","default":null,"not_null":true,"relation":"user_attribute_sources","collation":null},{"name":"source_namespace","type":"text","default":null,"not_null":true,"relation":"user_attribute_sources","collation":"default"},{"name":"connection_id","type":"uuid","default":null,"not_null":false,"relation":"user_attribute_sources","collation":null},{"name":"source_kind","type":"text","default":null,"not_null":true,"relation":"user_attribute_sources","collation":"default"},{"name":"source_authority","type":"text","default":null,"not_null":true,"relation":"user_attribute_sources","collation":"default"},{"name":"source_revision","type":"text","default":null,"not_null":true,"relation":"user_attribute_sources","collation":"default"},{"name":"observed_at","type":"bigint","default":null,"not_null":true,"relation":"user_attribute_sources","collation":null},{"name":"expires_at","type":"bigint","default":null,"not_null":false,"relation":"user_attribute_sources","collation":null},{"name":"attribute_values","type":"jsonb","default":null,"not_null":true,"relation":"user_attribute_sources","collation":null},{"name":"revision","type":"bigint","default":null,"not_null":true,"relation":"user_attribute_sources","collation":null},{"name":"updated_at","type":"timestamp with time zone","default":"now()","not_null":true,"relation":"user_attribute_sources","collation":null}],"indexes":[{"live":true,"name":"application_organizations_environment_id_domain_id_external_key","ready":true,"valid":true,"unique":true,"relation":"application_organizations","immediate":true,"definition":"CREATE UNIQUE INDEX application_organizations_environment_id_domain_id_external_key ON aegaeon.application_organizations USING btree (environment_id, domain_id, external_id)"},{"live":true,"name":"application_organizations_environment_id_domain_id_id_key","ready":true,"valid":true,"unique":true,"relation":"application_organizations","immediate":true,"definition":"CREATE UNIQUE INDEX application_organizations_environment_id_domain_id_id_key ON aegaeon.application_organizations USING btree (environment_id, domain_id, id)"},{"live":true,"name":"application_organizations_pkey","ready":true,"valid":true,"unique":true,"relation":"application_organizations","immediate":true,"definition":"CREATE UNIQUE INDEX application_organizations_pkey ON aegaeon.application_organizations USING btree (id)"},{"live":true,"name":"authorization_domain_targets_pkey","ready":true,"valid":true,"unique":true,"relation":"authorization_domain_targets","immediate":true,"definition":"CREATE UNIQUE INDEX authorization_domain_targets_pkey ON aegaeon.authorization_domain_targets USING btree (environment_id, audience)"},{"live":true,"name":"authorization_domains_environment_id_id_key","ready":true,"valid":true,"unique":true,"relation":"authorization_domains","immediate":true,"definition":"CREATE UNIQUE INDEX authorization_domains_environment_id_id_key ON aegaeon.authorization_domains USING btree (environment_id, id)"},{"live":true,"name":"authorization_domains_one_default","ready":true,"valid":true,"unique":true,"relation":"authorization_domains","immediate":true,"definition":"CREATE UNIQUE INDEX authorization_domains_one_default ON aegaeon.authorization_domains USING btree (environment_id) WHERE is_default"},{"live":true,"name":"authorization_domains_pkey","ready":true,"valid":true,"unique":true,"relation":"authorization_domains","immediate":true,"definition":"CREATE UNIQUE INDEX authorization_domains_pkey ON aegaeon.authorization_domains USING btree (id)"},{"live":true,"name":"lti_identifiers_pkey","ready":true,"valid":true,"unique":true,"relation":"lti_identifiers","immediate":true,"definition":"CREATE UNIQUE INDEX lti_identifiers_pkey ON aegaeon.lti_identifiers USING btree (environment_id, kind, identifier)"},{"live":true,"name":"lti_launch_intents_admission_idx","ready":true,"valid":true,"unique":false,"relation":"lti_launch_intents","immediate":true,"definition":"CREATE INDEX lti_launch_intents_admission_idx ON aegaeon.lti_launch_intents USING btree (environment_id, created_at) INCLUDE (producer_client_id, owner_id)"},{"live":true,"name":"lti_launch_intents_continuation_hash_key","ready":true,"valid":true,"unique":true,"relation":"lti_launch_intents","immediate":true,"definition":"CREATE UNIQUE INDEX lti_launch_intents_continuation_hash_key ON aegaeon.lti_launch_intents USING btree (continuation_hash)"},{"live":true,"name":"lti_launch_intents_expiry_idx","ready":true,"valid":true,"unique":false,"relation":"lti_launch_intents","immediate":true,"definition":"CREATE INDEX lti_launch_intents_expiry_idx ON aegaeon.lti_launch_intents USING btree (expires_at)"},{"live":true,"name":"lti_launch_intents_login_hint_hash_key","ready":true,"valid":true,"unique":true,"relation":"lti_launch_intents","immediate":true,"definition":"CREATE UNIQUE INDEX lti_launch_intents_login_hint_hash_key ON aegaeon.lti_launch_intents USING btree (login_hint_hash)"},{"live":true,"name":"lti_launch_intents_message_hint_hash_key","ready":true,"valid":true,"unique":true,"relation":"lti_launch_intents","immediate":true,"definition":"CREATE UNIQUE INDEX lti_launch_intents_message_hint_hash_key ON aegaeon.lti_launch_intents USING btree (message_hint_hash)"},{"live":true,"name":"lti_launch_intents_pkey","ready":true,"valid":true,"unique":true,"relation":"lti_launch_intents","immediate":true,"definition":"CREATE UNIQUE INDEX lti_launch_intents_pkey ON aegaeon.lti_launch_intents USING btree (id)"},{"live":true,"name":"lti_launch_intents_ticket_hash_key","ready":true,"valid":true,"unique":true,"relation":"lti_launch_intents","immediate":true,"definition":"CREATE UNIQUE INDEX lti_launch_intents_ticket_hash_key ON aegaeon.lti_launch_intents USING btree (ticket_hash)"},{"live":true,"name":"lti_registration_revisions_pkey","ready":true,"valid":true,"unique":true,"relation":"lti_registration_revisions","immediate":true,"definition":"CREATE UNIQUE INDEX lti_registration_revisions_pkey ON aegaeon.lti_registration_revisions USING btree (registration_id, revision)"},{"live":true,"name":"lti_registrations_environment_id_client_id_key","ready":true,"valid":true,"unique":true,"relation":"lti_registrations","immediate":true,"definition":"CREATE UNIQUE INDEX lti_registrations_environment_id_client_id_key ON aegaeon.lti_registrations USING btree (environment_id, client_id)"},{"live":true,"name":"lti_registrations_environment_id_id_key","ready":true,"valid":true,"unique":true,"relation":"lti_registrations","immediate":true,"definition":"CREATE UNIQUE INDEX lti_registrations_environment_id_id_key ON aegaeon.lti_registrations USING btree (environment_id, id)"},{"live":true,"name":"lti_registrations_pkey","ready":true,"valid":true,"unique":true,"relation":"lti_registrations","immediate":true,"definition":"CREATE UNIQUE INDEX lti_registrations_pkey ON aegaeon.lti_registrations USING btree (id)"},{"live":true,"name":"organization_admin_access_gra_environment_id_domain_id_user_key","ready":true,"valid":true,"unique":true,"relation":"organization_admin_access_grants","immediate":true,"definition":"CREATE UNIQUE INDEX organization_admin_access_gra_environment_id_domain_id_user_key ON aegaeon.organization_admin_access_grants USING btree (environment_id, domain_id, user_id, client_registration_id, root_id, creation_key)"},{"live":true,"name":"organization_admin_access_grants_pkey","ready":true,"valid":true,"unique":true,"relation":"organization_admin_access_grants","immediate":true,"definition":"CREATE UNIQUE INDEX organization_admin_access_grants_pkey ON aegaeon.organization_admin_access_grants USING btree (id)"},{"live":true,"name":"organization_authority_events_pkey","ready":true,"valid":true,"unique":true,"relation":"organization_authority_events","immediate":true,"definition":"CREATE UNIQUE INDEX organization_authority_events_pkey ON aegaeon.organization_authority_events USING btree (id)"},{"live":true,"name":"organization_authority_outbox_pkey","ready":true,"valid":true,"unique":true,"relation":"organization_authority_outbox","immediate":true,"definition":"CREATE UNIQUE INDEX organization_authority_outbox_pkey ON aegaeon.organization_authority_outbox USING btree (event_id)"},{"live":true,"name":"organization_authority_receipts_pkey","ready":true,"valid":true,"unique":true,"relation":"organization_authority_receipts","immediate":true,"definition":"CREATE UNIQUE INDEX organization_authority_receipts_pkey ON aegaeon.organization_authority_receipts USING btree (environment_id, domain_id, actor_id, actor_kind, client_id, client_registration_id, operation, idempotency_key)"},{"live":true,"name":"organization_client_binding_registration","ready":true,"valid":true,"unique":true,"relation":"organization_client_bindings","immediate":true,"definition":"CREATE UNIQUE INDEX organization_client_binding_registration ON aegaeon.organization_client_bindings USING btree (environment_id, domain_id, client_registration_id)"},{"live":true,"name":"organization_client_bindings_pkey","ready":true,"valid":true,"unique":true,"relation":"organization_client_bindings","immediate":true,"definition":"CREATE UNIQUE INDEX organization_client_bindings_pkey ON aegaeon.organization_client_bindings USING btree (id)"},{"live":true,"name":"organization_creation_receipt_environment_id_kind_selector__key","ready":true,"valid":true,"unique":true,"relation":"organization_creation_receipts","immediate":true,"definition":"CREATE UNIQUE INDEX organization_creation_receipt_environment_id_kind_selector__key ON aegaeon.organization_creation_receipts USING btree (environment_id, kind, selector_sha256)"},{"live":true,"name":"organization_creation_receipts_owner_id_key","ready":true,"valid":true,"unique":true,"relation":"organization_creation_receipts","immediate":true,"definition":"CREATE UNIQUE INDEX organization_creation_receipts_owner_id_key ON aegaeon.organization_creation_receipts USING btree (owner_id)"},{"live":true,"name":"organization_creation_receipts_pkey","ready":true,"valid":true,"unique":true,"relation":"organization_creation_receipts","immediate":true,"definition":"CREATE UNIQUE INDEX organization_creation_receipts_pkey ON aegaeon.organization_creation_receipts USING btree (environment_id, operation_id)"},{"live":true,"name":"organization_identity_request_environment_id_domain_id_invi_key","ready":true,"valid":true,"unique":true,"relation":"organization_identity_requests","immediate":true,"definition":"CREATE UNIQUE INDEX organization_identity_request_environment_id_domain_id_invi_key ON aegaeon.organization_identity_requests USING btree (environment_id, domain_id, invitation_id, request_key)"},{"live":true,"name":"organization_identity_requests_environment","ready":true,"valid":true,"unique":false,"relation":"organization_identity_requests","immediate":true,"definition":"CREATE INDEX organization_identity_requests_environment ON aegaeon.organization_identity_requests USING btree (environment_id, id)"},{"live":true,"name":"organization_identity_requests_pkey","ready":true,"valid":true,"unique":true,"relation":"organization_identity_requests","immediate":true,"definition":"CREATE UNIQUE INDEX organization_identity_requests_pkey ON aegaeon.organization_identity_requests USING btree (id)"},{"live":true,"name":"organization_import_operations_environment_id_domain_id_key","ready":true,"valid":true,"unique":true,"relation":"organization_import_operations","immediate":true,"definition":"CREATE UNIQUE INDEX organization_import_operations_environment_id_domain_id_key ON aegaeon.organization_import_operations USING btree (environment_id, domain_id)"},{"live":true,"name":"organization_import_operations_pkey","ready":true,"valid":true,"unique":true,"relation":"organization_import_operations","immediate":true,"definition":"CREATE UNIQUE INDEX organization_import_operations_pkey ON aegaeon.organization_import_operations USING btree (id)"},{"live":true,"name":"organization_invitation_chall_environment_id_domain_id_invi_key","ready":true,"valid":true,"unique":true,"relation":"organization_invitation_challenges","immediate":true,"definition":"CREATE UNIQUE INDEX organization_invitation_chall_environment_id_domain_id_invi_key ON aegaeon.organization_invitation_challenges USING btree (environment_id, domain_id, invitation_id, request_key)"},{"live":true,"name":"organization_invitation_challenges_pkey","ready":true,"valid":true,"unique":true,"relation":"organization_invitation_challenges","immediate":true,"definition":"CREATE UNIQUE INDEX organization_invitation_challenges_pkey ON aegaeon.organization_invitation_challenges USING btree (id)"},{"live":true,"name":"organization_invitations_domain_queue","ready":true,"valid":true,"unique":false,"relation":"organization_invitations","immediate":true,"definition":"CREATE INDEX organization_invitations_domain_queue ON aegaeon.organization_invitations USING btree (environment_id, domain_id, state, issued_at, id)"},{"live":true,"name":"organization_invitations_environment_id_domain_id_id_key","ready":true,"valid":true,"unique":true,"relation":"organization_invitations","immediate":true,"definition":"CREATE UNIQUE INDEX organization_invitations_environment_id_domain_id_id_key ON aegaeon.organization_invitations USING btree (environment_id, domain_id, id)"},{"live":true,"name":"organization_invitations_pkey","ready":true,"valid":true,"unique":true,"relation":"organization_invitations","immediate":true,"definition":"CREATE UNIQUE INDEX organization_invitations_pkey ON aegaeon.organization_invitations USING btree (id)"},{"live":true,"name":"organization_memberships_pkey","ready":true,"valid":true,"unique":true,"relation":"organization_memberships","immediate":true,"definition":"CREATE UNIQUE INDEX organization_memberships_pkey ON aegaeon.organization_memberships USING btree (environment_id, domain_id, organization_id, end_user_id)"},{"live":true,"name":"organization_operator_grants_environment_id_domain_id_admin_key","ready":true,"valid":true,"unique":true,"relation":"organization_operator_grants","immediate":true,"definition":"CREATE UNIQUE INDEX organization_operator_grants_environment_id_domain_id_admin_key ON aegaeon.organization_operator_grants USING btree (environment_id, domain_id, administrator_id)"},{"live":true,"name":"organization_operator_grants_pkey","ready":true,"valid":true,"unique":true,"relation":"organization_operator_grants","immediate":true,"definition":"CREATE UNIQUE INDEX organization_operator_grants_pkey ON aegaeon.organization_operator_grants USING btree (id)"},{"live":true,"name":"organization_role_definitions_pkey","ready":true,"valid":true,"unique":true,"relation":"organization_role_definitions","immediate":true,"definition":"CREATE UNIQUE INDEX organization_role_definitions_pkey ON aegaeon.organization_role_definitions USING btree (environment_id, domain_id, role_key)"},{"live":true,"name":"subject_history_restoration_pages_pkey","ready":true,"valid":true,"unique":true,"relation":"subject_history_restoration_pages","immediate":true,"definition":"CREATE UNIQUE INDEX subject_history_restoration_pages_pkey ON aegaeon.subject_history_restoration_pages USING btree (operation_id, after_sequence)"},{"live":true,"name":"subject_history_restorations_environment","ready":true,"valid":true,"unique":false,"relation":"subject_history_restorations","immediate":true,"definition":"CREATE INDEX subject_history_restorations_environment ON aegaeon.subject_history_restorations USING btree (environment_id)"},{"live":true,"name":"subject_history_restorations_pkey","ready":true,"valid":true,"unique":true,"relation":"subject_history_restorations","immediate":true,"definition":"CREATE UNIQUE INDEX subject_history_restorations_pkey ON aegaeon.subject_history_restorations USING btree (operation_id)"},{"live":true,"name":"user_attribute_sources_pkey","ready":true,"valid":true,"unique":true,"relation":"user_attribute_sources","immediate":true,"definition":"CREATE UNIQUE INDEX user_attribute_sources_pkey ON aegaeon.user_attribute_sources USING btree (environment_id, end_user_id, source_namespace)"}],"triggers":[{"name":"organization_import_hold","type":31,"enabled":"O","function":"organization_import_hold_guard","relation":"application_organizations","arguments":"","qualifier":null,"function_sha256":"1b5127bd2b5902f3dea40026ff342079e9f974628888e92b351dd1284430c698"},{"name":"organization_import_hold","type":31,"enabled":"O","function":"organization_import_hold_guard","relation":"authorization_domain_targets","arguments":"","qualifier":null,"function_sha256":"1b5127bd2b5902f3dea40026ff342079e9f974628888e92b351dd1284430c698"},{"name":"organization_import_hold","type":31,"enabled":"O","function":"organization_import_hold_guard","relation":"authorization_domains","arguments":"","qualifier":null,"function_sha256":"1b5127bd2b5902f3dea40026ff342079e9f974628888e92b351dd1284430c698"},{"name":"organization_support_policy_guard","type":19,"enabled":"O","function":"organization_support_policy_guard","relation":"authorization_domains","arguments":"","qualifier":null,"function_sha256":"92fde0e3b94ebb8e3d261689a17848cfaeefcf09790182c1a62c63a8426a219f"},{"name":"end_user_identity_owners_immutable","type":27,"enabled":"O","function":"subject_ownership_immutable","relation":"end_user_identity_owners","arguments":"","qualifier":null,"function_sha256":"1dc7cb3c7b4e7d3e04ceb7e9bde83ec95727fd255d15fd031cafa1979d69ba0b"},{"name":"end_user_identity_owners_no_truncate","type":34,"enabled":"O","function":"subject_ownership_immutable","relation":"end_user_identity_owners","arguments":"","qualifier":null,"function_sha256":"1dc7cb3c7b4e7d3e04ceb7e9bde83ec95727fd255d15fd031cafa1979d69ba0b"},{"name":"end_user_identity_owners_owner_insert","type":7,"enabled":"O","function":"subject_ownership_guard_insert","relation":"end_user_identity_owners","arguments":"","qualifier":null,"function_sha256":"ab9bcfbc5a9318f905708caf8aba574c404eeab0d7fdac2fc4ac1a448e6f5700"},{"name":"organization_identity_credential_guard","type":29,"enabled":"O","function":"organization_identity_credential_guard","relation":"end_user_password_credentials","arguments":"","qualifier":null,"function_sha256":"0509cce46c576e411dc2e4f5712f72a035bdf124b5974e5b7c25790e8265ae1f"},{"name":"organization_identity_profile_guard","type":29,"enabled":"O","function":"organization_identity_profile_guard","relation":"end_user_profiles","arguments":"","qualifier":null,"function_sha256":"680392524f1441ba46f4cb1549fa6ae67f506fc9f9cd644123539909d2df1000"},{"name":"end_user_subject_reservations_immutable","type":27,"enabled":"O","function":"subject_ownership_immutable","relation":"end_user_subject_reservations","arguments":"","qualifier":null,"function_sha256":"1dc7cb3c7b4e7d3e04ceb7e9bde83ec95727fd255d15fd031cafa1979d69ba0b"},{"name":"end_user_subject_reservations_no_truncate","type":34,"enabled":"O","function":"subject_ownership_immutable","relation":"end_user_subject_reservations","arguments":"","qualifier":null,"function_sha256":"1dc7cb3c7b4e7d3e04ceb7e9bde83ec95727fd255d15fd031cafa1979d69ba0b"},{"name":"end_user_subject_reservations_owner_insert","type":7,"enabled":"O","function":"subject_ownership_guard_insert","relation":"end_user_subject_reservations","arguments":"","qualifier":null,"function_sha256":"ab9bcfbc5a9318f905708caf8aba574c404eeab0d7fdac2fc4ac1a448e6f5700"},{"name":"end_users_subject_ownership","type":23,"enabled":"O","function":"subject_ownership_guard_user","relation":"end_users","arguments":"","qualifier":null,"function_sha256":"059eefb5a0776ba894174f0cc5979cca8d4b3435cfce35c20a2b05617ed524b1"},{"name":"organization_identity_guard","type":19,"enabled":"O","function":"organization_identity_guard","relation":"end_users","arguments":"","qualifier":null,"function_sha256":"1faf0ee116d7e00eb13e131def63a4aa853734c19e8a51032e374f49af87778a"},{"name":"environments_lifecycle_invariants","type":23,"enabled":"O","function":"enforce_environment_lifecycle_invariants","relation":"environments","arguments":"","qualifier":null,"function_sha256":"2a1f621d4c808381af01bc6926a47aacd411d96778a5e72c0c3f5c12f3025816"},{"name":"environments_subject_namespace_immutable","type":19,"enabled":"O","function":"subject_ownership_guard_environment","relation":"environments","arguments":"","qualifier":null,"function_sha256":"89f76c16b4b4f97e295df439e2e6e8593dbecca84cfe999c40ab7dd2d0cd299b"},{"name":"environments_subject_namespace_initialize","type":5,"enabled":"O","function":"subject_ownership_guard_environment","relation":"environments","arguments":"","qualifier":null,"function_sha256":"89f76c16b4b4f97e295df439e2e6e8593dbecca84cfe999c40ab7dd2d0cd299b"},{"name":"organization_identity_policy_guard","type":19,"enabled":"O","function":"organization_identity_policy_guard","relation":"environments","arguments":"","qualifier":null,"function_sha256":"3131b3bfad0303ccdddb3049f25862000cf791bca6bfc97780031e69ae328ef6"},{"name":"runtime_authority_notify_environments","type":29,"enabled":"O","function":"notify_runtime_authority_changed","relation":"environments","arguments":"","qualifier":null,"function_sha256":"a3e5775dcd003cb9e5aa6d7dd55c56a3832d122132e8c0f90af036ab7d52c1fd"},{"name":"lti_identifier_immutable","type":27,"enabled":"O","function":"lti_immutable_record","relation":"lti_identifiers","arguments":"","qualifier":null,"function_sha256":"1918fd5edcd390bfe0b9ff9c8f84578c3f22af49125a85b5c36c07c4f8ee4702"},{"name":"lti_identifier_no_truncate","type":34,"enabled":"O","function":"lti_immutable_record","relation":"lti_identifiers","arguments":"","qualifier":null,"function_sha256":"1918fd5edcd390bfe0b9ff9c8f84578c3f22af49125a85b5c36c07c4f8ee4702"},{"name":"lti_revision_immutable","type":27,"enabled":"O","function":"lti_immutable_record","relation":"lti_registration_revisions","arguments":"","qualifier":null,"function_sha256":"1918fd5edcd390bfe0b9ff9c8f84578c3f22af49125a85b5c36c07c4f8ee4702"},{"name":"lti_revision_no_truncate","type":34,"enabled":"O","function":"lti_immutable_record","relation":"lti_registration_revisions","arguments":"","qualifier":null,"function_sha256":"1918fd5edcd390bfe0b9ff9c8f84578c3f22af49125a85b5c36c07c4f8ee4702"},{"name":"organization_admin_access_guard","type":27,"enabled":"O","function":"organization_admin_access_guard","relation":"organization_admin_access_grants","arguments":"","qualifier":null,"function_sha256":"a4eb66b5628306146a3ede70db0499ef00e93248e84753f37f54f28ff14f0b45"},{"name":"organization_import_hold","type":31,"enabled":"O","function":"organization_import_hold_guard","relation":"organization_admin_access_grants","arguments":"","qualifier":null,"function_sha256":"1b5127bd2b5902f3dea40026ff342079e9f974628888e92b351dd1284430c698"},{"name":"organization_import_hold","type":31,"enabled":"O","function":"organization_import_hold_guard","relation":"organization_authority_events","arguments":"","qualifier":null,"function_sha256":"1b5127bd2b5902f3dea40026ff342079e9f974628888e92b351dd1284430c698"},{"name":"organization_import_hold","type":31,"enabled":"O","function":"organization_import_hold_guard","relation":"organization_authority_outbox","arguments":"","qualifier":null,"function_sha256":"1b5127bd2b5902f3dea40026ff342079e9f974628888e92b351dd1284430c698"},{"name":"organization_import_hold","type":31,"enabled":"O","function":"organization_import_hold_guard","relation":"organization_authority_receipts","arguments":"","qualifier":null,"function_sha256":"1b5127bd2b5902f3dea40026ff342079e9f974628888e92b351dd1284430c698"},{"name":"organization_import_hold","type":31,"enabled":"O","function":"organization_import_hold_guard","relation":"organization_client_bindings","arguments":"","qualifier":null,"function_sha256":"1b5127bd2b5902f3dea40026ff342079e9f974628888e92b351dd1284430c698"},{"name":"organization_creation_immutable","type":27,"enabled":"O","function":"subject_ownership_immutable","relation":"organization_creation_receipts","arguments":"","qualifier":null,"function_sha256":"1dc7cb3c7b4e7d3e04ceb7e9bde83ec95727fd255d15fd031cafa1979d69ba0b"},{"name":"organization_creation_no_truncate","type":34,"enabled":"O","function":"subject_ownership_immutable","relation":"organization_creation_receipts","arguments":"","qualifier":null,"function_sha256":"1dc7cb3c7b4e7d3e04ceb7e9bde83ec95727fd255d15fd031cafa1979d69ba0b"},{"name":"organization_creation_owner_insert","type":7,"enabled":"O","function":"subject_ownership_guard_insert","relation":"organization_creation_receipts","arguments":"","qualifier":null,"function_sha256":"ab9bcfbc5a9318f905708caf8aba574c404eeab0d7fdac2fc4ac1a448e6f5700"},{"name":"organization_import_hold","type":31,"enabled":"O","function":"organization_import_hold_guard","relation":"organization_identity_requests","arguments":"","qualifier":null,"function_sha256":"1b5127bd2b5902f3dea40026ff342079e9f974628888e92b351dd1284430c698"},{"name":"organization_import_hold","type":31,"enabled":"O","function":"organization_import_hold_guard","relation":"organization_invitation_challenges","arguments":"","qualifier":null,"function_sha256":"1b5127bd2b5902f3dea40026ff342079e9f974628888e92b351dd1284430c698"},{"name":"organization_import_hold","type":31,"enabled":"O","function":"organization_import_hold_guard","relation":"organization_invitations","arguments":"","qualifier":null,"function_sha256":"1b5127bd2b5902f3dea40026ff342079e9f974628888e92b351dd1284430c698"},{"name":"organization_import_hold","type":31,"enabled":"O","function":"organization_import_hold_guard","relation":"organization_memberships","arguments":"","qualifier":null,"function_sha256":"1b5127bd2b5902f3dea40026ff342079e9f974628888e92b351dd1284430c698"},{"name":"organization_import_hold","type":31,"enabled":"O","function":"organization_import_hold_guard","relation":"organization_operator_grants","arguments":"","qualifier":null,"function_sha256":"1b5127bd2b5902f3dea40026ff342079e9f974628888e92b351dd1284430c698"},{"name":"organization_import_hold","type":31,"enabled":"O","function":"organization_import_hold_guard","relation":"organization_role_definitions","arguments":"","qualifier":null,"function_sha256":"1b5127bd2b5902f3dea40026ff342079e9f974628888e92b351dd1284430c698"},{"name":"subject_history_restoration_pages_immutable","type":27,"enabled":"O","function":"subject_ownership_immutable","relation":"subject_history_restoration_pages","arguments":"","qualifier":null,"function_sha256":"1dc7cb3c7b4e7d3e04ceb7e9bde83ec95727fd255d15fd031cafa1979d69ba0b"},{"name":"subject_history_restoration_pages_no_truncate","type":34,"enabled":"O","function":"subject_ownership_immutable","relation":"subject_history_restoration_pages","arguments":"","qualifier":null,"function_sha256":"1dc7cb3c7b4e7d3e04ceb7e9bde83ec95727fd255d15fd031cafa1979d69ba0b"},{"name":"subject_history_restoration_pages_owner_insert","type":7,"enabled":"O","function":"subject_ownership_guard_insert","relation":"subject_history_restoration_pages","arguments":"","qualifier":null,"function_sha256":"ab9bcfbc5a9318f905708caf8aba574c404eeab0d7fdac2fc4ac1a448e6f5700"},{"name":"subject_history_restorations_immutable","type":27,"enabled":"O","function":"subject_ownership_immutable","relation":"subject_history_restorations","arguments":"","qualifier":null,"function_sha256":"1dc7cb3c7b4e7d3e04ceb7e9bde83ec95727fd255d15fd031cafa1979d69ba0b"},{"name":"subject_history_restorations_no_truncate","type":34,"enabled":"O","function":"subject_ownership_immutable","relation":"subject_history_restorations","arguments":"","qualifier":null,"function_sha256":"1dc7cb3c7b4e7d3e04ceb7e9bde83ec95727fd255d15fd031cafa1979d69ba0b"},{"name":"subject_history_restorations_owner_insert","type":7,"enabled":"O","function":"subject_ownership_guard_insert","relation":"subject_history_restorations","arguments":"","qualifier":null,"function_sha256":"ab9bcfbc5a9318f905708caf8aba574c404eeab0d7fdac2fc4ac1a448e6f5700"},{"name":"subject_ownership_adoptions_immutable","type":27,"enabled":"O","function":"subject_ownership_immutable","relation":"subject_ownership_adoptions","arguments":"","qualifier":null,"function_sha256":"1dc7cb3c7b4e7d3e04ceb7e9bde83ec95727fd255d15fd031cafa1979d69ba0b"},{"name":"subject_ownership_adoptions_no_truncate","type":34,"enabled":"O","function":"subject_ownership_immutable","relation":"subject_ownership_adoptions","arguments":"","qualifier":null,"function_sha256":"1dc7cb3c7b4e7d3e04ceb7e9bde83ec95727fd255d15fd031cafa1979d69ba0b"},{"name":"subject_ownership_adoptions_owner_insert","type":7,"enabled":"O","function":"subject_ownership_guard_insert","relation":"subject_ownership_adoptions","arguments":"","qualifier":null,"function_sha256":"ab9bcfbc5a9318f905708caf8aba574c404eeab0d7fdac2fc4ac1a448e6f5700"},{"name":"subject_ownership_namespaces_immutable","type":27,"enabled":"O","function":"subject_ownership_immutable","relation":"subject_ownership_namespaces","arguments":"","qualifier":null,"function_sha256":"1dc7cb3c7b4e7d3e04ceb7e9bde83ec95727fd255d15fd031cafa1979d69ba0b"},{"name":"subject_ownership_namespaces_no_truncate","type":34,"enabled":"O","function":"subject_ownership_immutable","relation":"subject_ownership_namespaces","arguments":"","qualifier":null,"function_sha256":"1dc7cb3c7b4e7d3e04ceb7e9bde83ec95727fd255d15fd031cafa1979d69ba0b"},{"name":"subject_ownership_namespaces_owner_insert","type":7,"enabled":"O","function":"subject_ownership_guard_insert","relation":"subject_ownership_namespaces","arguments":"","qualifier":null,"function_sha256":"ab9bcfbc5a9318f905708caf8aba574c404eeab0d7fdac2fc4ac1a448e6f5700"}],"constraints":[{"name":"application_organizations_created_at_not_null","deferred":false,"relation":"application_organizations","validated":true,"deferrable":false,"definition":"NOT NULL created_at"},{"name":"application_organizations_domain_id_not_null","deferred":false,"relation":"application_organizations","validated":true,"deferrable":false,"definition":"NOT NULL domain_id"},{"name":"application_organizations_environment_id_domain_id_external_key","deferred":false,"relation":"application_organizations","validated":true,"deferrable":false,"definition":"UNIQUE (environment_id, domain_id, external_id)"},{"name":"application_organizations_environment_id_domain_id_fkey","deferred":false,"relation":"application_organizations","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id, domain_id) REFERENCES aegaeon.authorization_domains(environment_id, id)"},{"name":"application_organizations_environment_id_domain_id_id_key","deferred":false,"relation":"application_organizations","validated":true,"deferrable":false,"definition":"UNIQUE (environment_id, domain_id, id)"},{"name":"application_organizations_environment_id_not_null","deferred":false,"relation":"application_organizations","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"application_organizations_external_id_check","deferred":false,"relation":"application_organizations","validated":true,"deferrable":false,"definition":"CHECK (((octet_length(external_id) >= 1) AND (octet_length(external_id) <= 256) AND (external_id !~ '[[:cntrl:]]'::text)))"},{"name":"application_organizations_external_id_not_null","deferred":false,"relation":"application_organizations","validated":true,"deferrable":false,"definition":"NOT NULL external_id"},{"name":"application_organizations_grant_generation_check","deferred":false,"relation":"application_organizations","validated":true,"deferrable":false,"definition":"CHECK ((grant_generation > 0))"},{"name":"application_organizations_grant_generation_not_null","deferred":false,"relation":"application_organizations","validated":true,"deferrable":false,"definition":"NOT NULL grant_generation"},{"name":"application_organizations_id_not_null","deferred":false,"relation":"application_organizations","validated":true,"deferrable":false,"definition":"NOT NULL id"},{"name":"application_organizations_pkey","deferred":false,"relation":"application_organizations","validated":true,"deferrable":false,"definition":"PRIMARY KEY (id)"},{"name":"application_organizations_revision_check","deferred":false,"relation":"application_organizations","validated":true,"deferrable":false,"definition":"CHECK ((revision > 0))"},{"name":"application_organizations_revision_not_null","deferred":false,"relation":"application_organizations","validated":true,"deferrable":false,"definition":"NOT NULL revision"},{"name":"application_organizations_state_check","deferred":false,"relation":"application_organizations","validated":true,"deferrable":false,"definition":"CHECK ((state = ANY (ARRAY['provisioning'::text, 'active'::text, 'suspended'::text, 'deleted'::text])))"},{"name":"application_organizations_state_not_null","deferred":false,"relation":"application_organizations","validated":true,"deferrable":false,"definition":"NOT NULL state"},{"name":"authorization_domain_targets_audience_check","deferred":false,"relation":"authorization_domain_targets","validated":true,"deferrable":false,"definition":"CHECK (((octet_length(audience) >= 1) AND (octet_length(audience) <= 2048)))"},{"name":"authorization_domain_targets_audience_not_null","deferred":false,"relation":"authorization_domain_targets","validated":true,"deferrable":false,"definition":"NOT NULL audience"},{"name":"authorization_domain_targets_domain_id_not_null","deferred":false,"relation":"authorization_domain_targets","validated":true,"deferrable":false,"definition":"NOT NULL domain_id"},{"name":"authorization_domain_targets_environment_id_domain_id_fkey","deferred":false,"relation":"authorization_domain_targets","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id, domain_id) REFERENCES aegaeon.authorization_domains(environment_id, id)"},{"name":"authorization_domain_targets_environment_id_not_null","deferred":false,"relation":"authorization_domain_targets","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"authorization_domain_targets_introspection_clients_check","deferred":false,"relation":"authorization_domain_targets","validated":true,"deferrable":false,"definition":"CHECK (((jsonb_typeof(introspection_clients) = 'array'::text) AND (jsonb_array_length(introspection_clients) <= 8) AND (octet_length((introspection_clients)::text) <= 8192)))"},{"name":"authorization_domain_targets_introspection_clients_not_null","deferred":false,"relation":"authorization_domain_targets","validated":true,"deferrable":false,"definition":"NOT NULL introspection_clients"},{"name":"authorization_domain_targets_management_not_null","deferred":false,"relation":"authorization_domain_targets","validated":true,"deferrable":false,"definition":"NOT NULL management"},{"name":"authorization_domain_targets_pkey","deferred":false,"relation":"authorization_domain_targets","validated":true,"deferrable":false,"definition":"PRIMARY KEY (environment_id, audience)"},{"name":"authorization_domains_enabled_not_null","deferred":false,"relation":"authorization_domains","validated":true,"deferrable":false,"definition":"NOT NULL enabled"},{"name":"authorization_domains_environment_id_fkey","deferred":false,"relation":"authorization_domains","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id)"},{"name":"authorization_domains_environment_id_id_key","deferred":false,"relation":"authorization_domains","validated":true,"deferrable":false,"definition":"UNIQUE (environment_id, id)"},{"name":"authorization_domains_environment_id_not_null","deferred":false,"relation":"authorization_domains","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"authorization_domains_id_not_null","deferred":false,"relation":"authorization_domains","validated":true,"deferrable":false,"definition":"NOT NULL id"},{"name":"authorization_domains_invitation_delivery_check","deferred":false,"relation":"authorization_domains","validated":true,"deferrable":false,"definition":"CHECK (((invitation_delivery IS NULL) OR ((jsonb_typeof(invitation_delivery) = 'object'::text) AND (octet_length((invitation_delivery)::text) <= 4096))))"},{"name":"authorization_domains_is_default_not_null","deferred":false,"relation":"authorization_domains","validated":true,"deferrable":false,"definition":"NOT NULL is_default"},{"name":"authorization_domains_name_check","deferred":false,"relation":"authorization_domains","validated":true,"deferrable":false,"definition":"CHECK (((octet_length(name) >= 1) AND (octet_length(name) <= 256)))"},{"name":"authorization_domains_name_not_null","deferred":false,"relation":"authorization_domains","validated":true,"deferrable":false,"definition":"NOT NULL name"},{"name":"authorization_domains_pkey","deferred":false,"relation":"authorization_domains","validated":true,"deferrable":false,"definition":"PRIMARY KEY (id)"},{"name":"authorization_domains_revision_check","deferred":false,"relation":"authorization_domains","validated":true,"deferrable":false,"definition":"CHECK ((revision > 0))"},{"name":"authorization_domains_revision_not_null","deferred":false,"relation":"authorization_domains","validated":true,"deferrable":false,"definition":"NOT NULL revision"},{"name":"authorization_domains_support_policy_revision_check","deferred":false,"relation":"authorization_domains","validated":true,"deferrable":false,"definition":"CHECK ((support_policy_revision > 0))"},{"name":"authorization_domains_support_policy_revision_not_null","deferred":false,"relation":"authorization_domains","validated":true,"deferrable":false,"definition":"NOT NULL support_policy_revision"},{"name":"organization_import_inactive","deferred":false,"relation":"authorization_domains","validated":true,"deferrable":false,"definition":"CHECK (((import_operation_id IS NULL) OR (NOT enabled)))"},{"name":"organization_support_policy_object","deferred":false,"relation":"authorization_domains","validated":true,"deferrable":false,"definition":"CHECK (((support_policy IS NULL) OR ((jsonb_typeof(support_policy) = 'object'::text) AND (octet_length((support_policy)::text) <= 65536))))"},{"name":"end_user_identity_owners_environment_id_fkey","deferred":false,"relation":"end_user_identity_owners","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id) REFERENCES aegaeon.subject_ownership_namespaces(environment_id) ON DELETE RESTRICT"},{"name":"end_user_identity_owners_environment_id_not_null","deferred":false,"relation":"end_user_identity_owners","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"end_user_identity_owners_owner_id_environment_id_key","deferred":false,"relation":"end_user_identity_owners","validated":true,"deferrable":false,"definition":"UNIQUE (owner_id, environment_id)"},{"name":"end_user_identity_owners_owner_id_not_null","deferred":false,"relation":"end_user_identity_owners","validated":true,"deferrable":false,"definition":"NOT NULL owner_id"},{"name":"end_user_identity_owners_pkey","deferred":false,"relation":"end_user_identity_owners","validated":true,"deferrable":false,"definition":"PRIMARY KEY (owner_id)"},{"name":"end_user_identity_owners_recorded_at_not_null","deferred":false,"relation":"end_user_identity_owners","validated":true,"deferrable":false,"definition":"NOT NULL recorded_at"},{"name":"end_user_password_credentials_created_at_not_null","deferred":false,"relation":"end_user_password_credentials","validated":true,"deferrable":false,"definition":"NOT NULL created_at"},{"name":"end_user_password_credentials_created_by_administrator_id_fkey","deferred":false,"relation":"end_user_password_credentials","validated":true,"deferrable":false,"definition":"FOREIGN KEY (created_by_administrator_id) REFERENCES aegaeon.administrators(id) ON DELETE SET NULL"},{"name":"end_user_password_credentials_end_user_id_fkey","deferred":false,"relation":"end_user_password_credentials","validated":true,"deferrable":false,"definition":"FOREIGN KEY (end_user_id) REFERENCES aegaeon.end_users(id) ON DELETE RESTRICT"},{"name":"end_user_password_credentials_end_user_id_not_null","deferred":false,"relation":"end_user_password_credentials","validated":true,"deferrable":false,"definition":"NOT NULL end_user_id"},{"name":"end_user_password_credentials_id_not_null","deferred":false,"relation":"end_user_password_credentials","validated":true,"deferrable":false,"definition":"NOT NULL id"},{"name":"end_user_password_credentials_last_used_after_created","deferred":false,"relation":"end_user_password_credentials","validated":true,"deferrable":false,"definition":"CHECK (((last_used_at IS NULL) OR (last_used_at >= created_at)))"},{"name":"end_user_password_credentials_password_hash_not_null","deferred":false,"relation":"end_user_password_credentials","validated":true,"deferrable":false,"definition":"NOT NULL password_hash"},{"name":"end_user_password_credentials_pkey","deferred":false,"relation":"end_user_password_credentials","validated":true,"deferrable":false,"definition":"PRIMARY KEY (id)"},{"name":"end_user_password_credentials_revoked_by_administrator_id_fkey","deferred":false,"relation":"end_user_password_credentials","validated":true,"deferrable":false,"definition":"FOREIGN KEY (revoked_by_administrator_id) REFERENCES aegaeon.administrators(id) ON DELETE SET NULL"},{"name":"end_user_password_credentials_status_not_null","deferred":false,"relation":"end_user_password_credentials","validated":true,"deferrable":false,"definition":"NOT NULL status"},{"name":"end_user_password_credentials_updated_at_not_null","deferred":false,"relation":"end_user_password_credentials","validated":true,"deferrable":false,"definition":"NOT NULL updated_at"},{"name":"end_user_profiles_created_at_not_null","deferred":false,"relation":"end_user_profiles","validated":true,"deferrable":false,"definition":"NOT NULL created_at"},{"name":"end_user_profiles_custom_claims_not_null","deferred":false,"relation":"end_user_profiles","validated":true,"deferrable":false,"definition":"NOT NULL custom_claims"},{"name":"end_user_profiles_custom_claims_object","deferred":false,"relation":"end_user_profiles","validated":true,"deferrable":false,"definition":"CHECK ((jsonb_typeof(custom_claims) = 'object'::text))"},{"name":"end_user_profiles_email_verified_not_null","deferred":false,"relation":"end_user_profiles","validated":true,"deferrable":false,"definition":"NOT NULL email_verified"},{"name":"end_user_profiles_end_user_id_fkey","deferred":false,"relation":"end_user_profiles","validated":true,"deferrable":false,"definition":"FOREIGN KEY (end_user_id) REFERENCES aegaeon.end_users(id) ON DELETE CASCADE"},{"name":"end_user_profiles_end_user_id_not_null","deferred":false,"relation":"end_user_profiles","validated":true,"deferrable":false,"definition":"NOT NULL end_user_id"},{"name":"end_user_profiles_pkey","deferred":false,"relation":"end_user_profiles","validated":true,"deferrable":false,"definition":"PRIMARY KEY (end_user_id)"},{"name":"end_user_profiles_profile_version_not_null","deferred":false,"relation":"end_user_profiles","validated":true,"deferrable":false,"definition":"NOT NULL profile_version"},{"name":"end_user_profiles_profile_version_positive","deferred":false,"relation":"end_user_profiles","validated":true,"deferrable":false,"definition":"CHECK ((profile_version > 0))"},{"name":"end_user_profiles_subject_policy_not_null","deferred":false,"relation":"end_user_profiles","validated":true,"deferrable":false,"definition":"NOT NULL subject_policy"},{"name":"end_user_profiles_subject_policy_valid","deferred":false,"relation":"end_user_profiles","validated":true,"deferrable":false,"definition":"CHECK ((subject_policy = 'explicit'::text))"},{"name":"end_user_profiles_updated_at_not_null","deferred":false,"relation":"end_user_profiles","validated":true,"deferrable":false,"definition":"NOT NULL updated_at"},{"name":"end_user_profiles_verified_delivery_address_check","deferred":false,"relation":"end_user_profiles","validated":true,"deferrable":false,"definition":"CHECK (((verified_delivery_address IS NULL) OR ((octet_length(verified_delivery_address) >= 3) AND (octet_length(verified_delivery_address) <= 254))))"},{"name":"end_user_subject_reservations_environment_id_fkey","deferred":false,"relation":"end_user_subject_reservations","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id) REFERENCES aegaeon.subject_ownership_namespaces(environment_id) ON DELETE RESTRICT"},{"name":"end_user_subject_reservations_environment_id_not_null","deferred":false,"relation":"end_user_subject_reservations","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"end_user_subject_reservations_owner_id_not_null","deferred":false,"relation":"end_user_subject_reservations","validated":true,"deferrable":false,"definition":"NOT NULL owner_id"},{"name":"end_user_subject_reservations_pkey","deferred":false,"relation":"end_user_subject_reservations","validated":true,"deferrable":false,"definition":"PRIMARY KEY (environment_id, subject)"},{"name":"end_user_subject_reservations_recorded_at_not_null","deferred":false,"relation":"end_user_subject_reservations","validated":true,"deferrable":false,"definition":"NOT NULL recorded_at"},{"name":"end_user_subject_reservations_subject_check","deferred":false,"relation":"end_user_subject_reservations","validated":true,"deferrable":false,"definition":"CHECK (aegaeon.subject_ownership_valid_subject(subject))"},{"name":"end_user_subject_reservations_subject_not_null","deferred":false,"relation":"end_user_subject_reservations","validated":true,"deferrable":false,"definition":"NOT NULL subject"},{"name":"subject_reservations_owner_environment_fkey","deferred":false,"relation":"end_user_subject_reservations","validated":true,"deferrable":false,"definition":"FOREIGN KEY (owner_id, environment_id) REFERENCES aegaeon.end_user_identity_owners(owner_id, environment_id) ON DELETE RESTRICT"},{"name":"end_users_created_at_not_null","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"NOT NULL created_at"},{"name":"end_users_email_lowercase","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"CHECK (((email IS NULL) OR (email = lower(email))))"},{"name":"end_users_environment_id_fkey","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT"},{"name":"end_users_environment_id_id_unique","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"UNIQUE (environment_id, id)"},{"name":"end_users_environment_id_not_null","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"end_users_id_not_null","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"NOT NULL id"},{"name":"end_users_organization_identity_revision_check","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"CHECK ((organization_identity_revision > 0))"},{"name":"end_users_organization_identity_revision_not_null","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"NOT NULL organization_identity_revision"},{"name":"end_users_organization_reauthentication_after_check","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"CHECK ((organization_reauthentication_after >= 0))"},{"name":"end_users_organization_reauthentication_after_not_null","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"NOT NULL organization_reauthentication_after"},{"name":"end_users_pkey","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"PRIMARY KEY (id)"},{"name":"end_users_status_not_null","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"NOT NULL status"},{"name":"end_users_subject_format","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"CHECK (aegaeon.subject_ownership_valid_subject(subject))"},{"name":"end_users_subject_not_null","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"NOT NULL subject"},{"name":"end_users_updated_at_not_null","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"NOT NULL updated_at"},{"name":"environments_active_configuration_version_same_environment_fkey","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"FOREIGN KEY (id, active_configuration_version_id) REFERENCES aegaeon.configuration_versions(environment_id, id) ON DELETE RESTRICT"},{"name":"environments_created_at_not_null","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"NOT NULL created_at"},{"name":"environments_id_not_null","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"NOT NULL id"},{"name":"environments_issuer_host_check","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"CHECK (((issuer_host = lower(issuer_host)) AND (POSITION(('://'::text) IN (issuer_host)) = 0) AND (POSITION(('/'::text) IN (issuer_host)) = 0) AND (POSITION(('?'::text) IN (issuer_host)) = 0) AND (POSITION(('#'::text) IN (issuer_host)) = 0)))"},{"name":"environments_issuer_host_not_null","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"NOT NULL issuer_host"},{"name":"environments_name_not_null","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"NOT NULL name"},{"name":"environments_organization_identity_policy_revision_check","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"CHECK ((organization_identity_policy_revision > 0))"},{"name":"environments_organization_identity_policy_revision_not_null","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"NOT NULL organization_identity_policy_revision"},{"name":"environments_pkey","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"PRIMARY KEY (id)"},{"name":"environments_slug_dns_label","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"CHECK (((slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'::text) AND (slug = lower(slug))))"},{"name":"environments_slug_not_null","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"NOT NULL slug"},{"name":"environments_status_not_null","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"NOT NULL status"},{"name":"environments_tenant_id_fkey","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"FOREIGN KEY (tenant_id) REFERENCES aegaeon.tenants(id) ON DELETE RESTRICT"},{"name":"environments_tenant_id_not_null","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"NOT NULL tenant_id"},{"name":"environments_updated_at_not_null","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"NOT NULL updated_at"},{"name":"organization_identity_policy_object","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"CHECK (((organization_identity_policy IS NULL) OR (jsonb_typeof(organization_identity_policy) = 'object'::text)))"},{"name":"lti_identifiers_deployment_id_not_null","deferred":false,"relation":"lti_identifiers","validated":true,"deferrable":false,"definition":"NOT NULL deployment_id"},{"name":"lti_identifiers_environment_id_not_null","deferred":false,"relation":"lti_identifiers","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"lti_identifiers_environment_id_registration_id_fkey","deferred":false,"relation":"lti_identifiers","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id, registration_id) REFERENCES aegaeon.lti_registrations(environment_id, id) ON DELETE RESTRICT"},{"name":"lti_identifiers_identifier_check","deferred":false,"relation":"lti_identifiers","validated":true,"deferrable":false,"definition":"CHECK (((octet_length(identifier) >= 1) AND (octet_length(identifier) <= 255)))"},{"name":"lti_identifiers_identifier_not_null","deferred":false,"relation":"lti_identifiers","validated":true,"deferrable":false,"definition":"NOT NULL identifier"},{"name":"lti_identifiers_kind_check","deferred":false,"relation":"lti_identifiers","validated":true,"deferrable":false,"definition":"CHECK ((kind = ANY (ARRAY['deployment'::text, 'resource_link'::text])))"},{"name":"lti_identifiers_kind_not_null","deferred":false,"relation":"lti_identifiers","validated":true,"deferrable":false,"definition":"NOT NULL kind"},{"name":"lti_identifiers_pkey","deferred":false,"relation":"lti_identifiers","validated":true,"deferrable":false,"definition":"PRIMARY KEY (environment_id, kind, identifier)"},{"name":"lti_identifiers_registration_id_not_null","deferred":false,"relation":"lti_identifiers","validated":true,"deferrable":false,"definition":"NOT NULL registration_id"},{"name":"lti_launch_intents_authorization_request_check","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"CHECK (((authorization_request IS NULL) OR (octet_length((authorization_request)::text) <= 65536)))"},{"name":"lti_launch_intents_check","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"CHECK (((expires_at > created_at) AND (expires_at <= (created_at + 300))))"},{"name":"lti_launch_intents_continuation_hash_key","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"UNIQUE (continuation_hash)"},{"name":"lti_launch_intents_created_at_not_null","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"NOT NULL created_at"},{"name":"lti_launch_intents_deployment_id_not_null","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"NOT NULL deployment_id"},{"name":"lti_launch_intents_environment_id_not_null","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"lti_launch_intents_environment_id_registration_id_fkey","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id, registration_id) REFERENCES aegaeon.lti_registrations(environment_id, id) ON DELETE RESTRICT"},{"name":"lti_launch_intents_expires_at_not_null","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"NOT NULL expires_at"},{"name":"lti_launch_intents_id_not_null","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"NOT NULL id"},{"name":"lti_launch_intents_login_hint_hash_key","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"UNIQUE (login_hint_hash)"},{"name":"lti_launch_intents_message_hint_hash_key","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"UNIQUE (message_hint_hash)"},{"name":"lti_launch_intents_owner_id_not_null","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"NOT NULL owner_id"},{"name":"lti_launch_intents_pkey","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"PRIMARY KEY (id)"},{"name":"lti_launch_intents_producer_client_id_not_null","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"NOT NULL producer_client_id"},{"name":"lti_launch_intents_producer_metadata_check","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"CHECK ((octet_length((producer_metadata)::text) <= 65536))"},{"name":"lti_launch_intents_producer_metadata_not_null","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"NOT NULL producer_metadata"},{"name":"lti_launch_intents_producer_token_digest_not_null","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"NOT NULL producer_token_digest"},{"name":"lti_launch_intents_registration_id_not_null","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"NOT NULL registration_id"},{"name":"lti_launch_intents_registration_id_revision_fkey","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"FOREIGN KEY (registration_id, revision) REFERENCES aegaeon.lti_registration_revisions(registration_id, revision) ON DELETE RESTRICT"},{"name":"lti_launch_intents_resource_link_id_not_null","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"NOT NULL resource_link_id"},{"name":"lti_launch_intents_revision_not_null","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"NOT NULL revision"},{"name":"lti_launch_intents_roles_check","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"CHECK ((jsonb_typeof(roles) = 'array'::text))"},{"name":"lti_launch_intents_roles_not_null","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"NOT NULL roles"},{"name":"lti_launch_intents_runtime_fingerprint_not_null","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"NOT NULL runtime_fingerprint"},{"name":"lti_launch_intents_runtime_revision_not_null","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"NOT NULL runtime_revision"},{"name":"lti_launch_intents_status_check","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"CHECK ((status = ANY (ARRAY['pending'::text, 'confirmed'::text, 'initiated'::text, 'consumed'::text, 'cancelled'::text])))"},{"name":"lti_launch_intents_status_not_null","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"NOT NULL status"},{"name":"lti_launch_intents_subject_not_null","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"NOT NULL subject"},{"name":"lti_launch_intents_ticket_hash_key","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"UNIQUE (ticket_hash)"},{"name":"lti_launch_intents_ticket_hash_not_null","deferred":false,"relation":"lti_launch_intents","validated":true,"deferrable":false,"definition":"NOT NULL ticket_hash"},{"name":"lti_registration_revisions_author_id_fkey","deferred":false,"relation":"lti_registration_revisions","validated":true,"deferrable":false,"definition":"FOREIGN KEY (author_id) REFERENCES aegaeon.administrators(id) ON DELETE RESTRICT"},{"name":"lti_registration_revisions_author_id_not_null","deferred":false,"relation":"lti_registration_revisions","validated":true,"deferrable":false,"definition":"NOT NULL author_id"},{"name":"lti_registration_revisions_created_at_not_null","deferred":false,"relation":"lti_registration_revisions","validated":true,"deferrable":false,"definition":"NOT NULL created_at"},{"name":"lti_registration_revisions_document_check","deferred":false,"relation":"lti_registration_revisions","validated":true,"deferrable":false,"definition":"CHECK (((jsonb_typeof(document) = 'object'::text) AND (octet_length((document)::text) <= 1048576)))"},{"name":"lti_registration_revisions_document_not_null","deferred":false,"relation":"lti_registration_revisions","validated":true,"deferrable":false,"definition":"NOT NULL document"},{"name":"lti_registration_revisions_pkey","deferred":false,"relation":"lti_registration_revisions","validated":true,"deferrable":false,"definition":"PRIMARY KEY (registration_id, revision)"},{"name":"lti_registration_revisions_registration_id_fkey","deferred":false,"relation":"lti_registration_revisions","validated":true,"deferrable":false,"definition":"FOREIGN KEY (registration_id) REFERENCES aegaeon.lti_registrations(id) ON DELETE RESTRICT"},{"name":"lti_registration_revisions_registration_id_not_null","deferred":false,"relation":"lti_registration_revisions","validated":true,"deferrable":false,"definition":"NOT NULL registration_id"},{"name":"lti_registration_revisions_revision_check","deferred":false,"relation":"lti_registration_revisions","validated":true,"deferrable":false,"definition":"CHECK ((revision > 0))"},{"name":"lti_registration_revisions_revision_not_null","deferred":false,"relation":"lti_registration_revisions","validated":true,"deferrable":false,"definition":"NOT NULL revision"},{"name":"lti_active_revision_fkey","deferred":true,"relation":"lti_registrations","validated":true,"deferrable":true,"definition":"FOREIGN KEY (id, active_revision) REFERENCES aegaeon.lti_registration_revisions(registration_id, revision) DEFERRABLE INITIALLY DEFERRED"},{"name":"lti_registrations_check","deferred":false,"relation":"lti_registrations","validated":true,"deferrable":false,"definition":"CHECK (((active_revision IS NULL) OR ((active_revision > 0) AND (active_revision <= revision))))"},{"name":"lti_registrations_client_id_not_null","deferred":false,"relation":"lti_registrations","validated":true,"deferrable":false,"definition":"NOT NULL client_id"},{"name":"lti_registrations_client_record_id_fkey","deferred":false,"relation":"lti_registrations","validated":true,"deferrable":false,"definition":"FOREIGN KEY (client_record_id) REFERENCES aegaeon.clients(id) ON DELETE RESTRICT"},{"name":"lti_registrations_client_record_id_not_null","deferred":false,"relation":"lti_registrations","validated":true,"deferrable":false,"definition":"NOT NULL client_record_id"},{"name":"lti_registrations_environment_id_client_id_key","deferred":false,"relation":"lti_registrations","validated":true,"deferrable":false,"definition":"UNIQUE (environment_id, client_id)"},{"name":"lti_registrations_environment_id_fkey","deferred":false,"relation":"lti_registrations","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT"},{"name":"lti_registrations_environment_id_id_key","deferred":false,"relation":"lti_registrations","validated":true,"deferrable":false,"definition":"UNIQUE (environment_id, id)"},{"name":"lti_registrations_environment_id_not_null","deferred":false,"relation":"lti_registrations","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"lti_registrations_id_not_null","deferred":false,"relation":"lti_registrations","validated":true,"deferrable":false,"definition":"NOT NULL id"},{"name":"lti_registrations_pkey","deferred":false,"relation":"lti_registrations","validated":true,"deferrable":false,"definition":"PRIMARY KEY (id)"},{"name":"lti_registrations_revision_check","deferred":false,"relation":"lti_registrations","validated":true,"deferrable":false,"definition":"CHECK ((revision >= 0))"},{"name":"lti_registrations_revision_not_null","deferred":false,"relation":"lti_registrations","validated":true,"deferrable":false,"definition":"NOT NULL revision"},{"name":"organization_admin_access_gra_environment_id_domain_id_org_fkey","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id, domain_id, organization_id) REFERENCES aegaeon.application_organizations(environment_id, domain_id, id)"},{"name":"organization_admin_access_gra_environment_id_domain_id_user_key","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"UNIQUE (environment_id, domain_id, user_id, client_registration_id, root_id, creation_key)"},{"name":"organization_admin_access_grant_client_registration_id_not_null","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"NOT NULL client_registration_id"},{"name":"organization_admin_access_grants_active_not_null","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"NOT NULL active"},{"name":"organization_admin_access_grants_authority_check","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"CHECK (((jsonb_typeof(authority) = 'object'::text) AND (octet_length((authority)::text) <= 65536)))"},{"name":"organization_admin_access_grants_authority_not_null","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"NOT NULL authority"},{"name":"organization_admin_access_grants_check","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"CHECK (((expires_at > issued_at) AND ((expires_at - issued_at) <= 300)))"},{"name":"organization_admin_access_grants_check1","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"CHECK (((active AND (revision = 1) AND (revocation_key IS NULL) AND (revocation_digest IS NULL)) OR ((NOT active) AND (revision = 2) AND (revocation_key IS NOT NULL) AND (revocation_digest IS NOT NULL))))"},{"name":"organization_admin_access_grants_creation_key_check","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"CHECK (((octet_length(creation_key) >= 1) AND (octet_length(creation_key) <= 128)))"},{"name":"organization_admin_access_grants_creation_key_not_null","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"NOT NULL creation_key"},{"name":"organization_admin_access_grants_domain_id_not_null","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"NOT NULL domain_id"},{"name":"organization_admin_access_grants_environment_id_not_null","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"organization_admin_access_grants_expires_at_not_null","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"NOT NULL expires_at"},{"name":"organization_admin_access_grants_id_not_null","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"NOT NULL id"},{"name":"organization_admin_access_grants_issued_at_check","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"CHECK ((issued_at > 0))"},{"name":"organization_admin_access_grants_issued_at_not_null","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"NOT NULL issued_at"},{"name":"organization_admin_access_grants_organization_id_not_null","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"NOT NULL organization_id"},{"name":"organization_admin_access_grants_pkey","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"PRIMARY KEY (id)"},{"name":"organization_admin_access_grants_request_digest_check","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"CHECK ((octet_length(request_digest) = 32))"},{"name":"organization_admin_access_grants_request_digest_not_null","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"NOT NULL request_digest"},{"name":"organization_admin_access_grants_revision_check","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"CHECK ((revision = ANY (ARRAY[(1)::bigint, (2)::bigint])))"},{"name":"organization_admin_access_grants_revision_not_null","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"NOT NULL revision"},{"name":"organization_admin_access_grants_revocation_digest_check","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"CHECK ((octet_length(revocation_digest) = 32))"},{"name":"organization_admin_access_grants_revocation_key_check","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"CHECK (((octet_length(revocation_key) >= 1) AND (octet_length(revocation_key) <= 128)))"},{"name":"organization_admin_access_grants_root_id_check","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"CHECK (((octet_length(root_id) >= 1) AND (octet_length(root_id) <= 2048)))"},{"name":"organization_admin_access_grants_root_id_not_null","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"NOT NULL root_id"},{"name":"organization_admin_access_grants_user_id_not_null","deferred":false,"relation":"organization_admin_access_grants","validated":true,"deferrable":false,"definition":"NOT NULL user_id"},{"name":"organization_authority_event_scope","deferred":false,"relation":"organization_authority_events","validated":true,"deferrable":false,"definition":"CHECK ((((organization_id IS NULL) AND (event_type ~~ 'domain.%'::text)) OR ((organization_id IS NOT NULL) AND (event_type !~~ 'domain.%'::text))))"},{"name":"organization_authority_events_actor_id_not_null","deferred":false,"relation":"organization_authority_events","validated":true,"deferrable":false,"definition":"NOT NULL actor_id"},{"name":"organization_authority_events_actor_kind_check","deferred":false,"relation":"organization_authority_events","validated":true,"deferrable":false,"definition":"CHECK ((actor_kind = ANY (ARRAY['operator'::text, 'member'::text])))"},{"name":"organization_authority_events_actor_kind_not_null","deferred":false,"relation":"organization_authority_events","validated":true,"deferrable":false,"definition":"NOT NULL actor_kind"},{"name":"organization_authority_events_client_id_check","deferred":false,"relation":"organization_authority_events","validated":true,"deferrable":false,"definition":"CHECK (((octet_length(client_id) >= 1) AND (octet_length(client_id) <= 255)))"},{"name":"organization_authority_events_client_id_not_null","deferred":false,"relation":"organization_authority_events","validated":true,"deferrable":false,"definition":"NOT NULL client_id"},{"name":"organization_authority_events_created_at_not_null","deferred":false,"relation":"organization_authority_events","validated":true,"deferrable":false,"definition":"NOT NULL created_at"},{"name":"organization_authority_events_data_check","deferred":false,"relation":"organization_authority_events","validated":true,"deferrable":false,"definition":"CHECK ((jsonb_typeof(data) = 'object'::text))"},{"name":"organization_authority_events_data_not_null","deferred":false,"relation":"organization_authority_events","validated":true,"deferrable":false,"definition":"NOT NULL data"},{"name":"organization_authority_events_domain_id_not_null","deferred":false,"relation":"organization_authority_events","validated":true,"deferrable":false,"definition":"NOT NULL domain_id"},{"name":"organization_authority_events_environment_id_domain_id_org_fkey","deferred":false,"relation":"organization_authority_events","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id, domain_id, organization_id) REFERENCES aegaeon.application_organizations(environment_id, domain_id, id)"},{"name":"organization_authority_events_environment_id_not_null","deferred":false,"relation":"organization_authority_events","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"organization_authority_events_event_type_not_null","deferred":false,"relation":"organization_authority_events","validated":true,"deferrable":false,"definition":"NOT NULL event_type"},{"name":"organization_authority_events_id_not_null","deferred":false,"relation":"organization_authority_events","validated":true,"deferrable":false,"definition":"NOT NULL id"},{"name":"organization_authority_events_pkey","deferred":false,"relation":"organization_authority_events","validated":true,"deferrable":false,"definition":"PRIMARY KEY (id)"},{"name":"organization_authority_events_reason_check","deferred":false,"relation":"organization_authority_events","validated":true,"deferrable":false,"definition":"CHECK (((octet_length(reason) >= 1) AND (octet_length(reason) <= 1024)))"},{"name":"organization_authority_events_reason_not_null","deferred":false,"relation":"organization_authority_events","validated":true,"deferrable":false,"definition":"NOT NULL reason"},{"name":"organization_authority_events_request_id_check","deferred":false,"relation":"organization_authority_events","validated":true,"deferrable":false,"definition":"CHECK (((octet_length(request_id) >= 1) AND (octet_length(request_id) <= 255)))"},{"name":"organization_authority_events_request_id_not_null","deferred":false,"relation":"organization_authority_events","validated":true,"deferrable":false,"definition":"NOT NULL request_id"},{"name":"organization_authority_outbox_attempts_check","deferred":false,"relation":"organization_authority_outbox","validated":true,"deferrable":false,"definition":"CHECK ((attempts >= 0))"},{"name":"organization_authority_outbox_attempts_not_null","deferred":false,"relation":"organization_authority_outbox","validated":true,"deferrable":false,"definition":"NOT NULL attempts"},{"name":"organization_authority_outbox_event_id_fkey","deferred":false,"relation":"organization_authority_outbox","validated":true,"deferrable":false,"definition":"FOREIGN KEY (event_id) REFERENCES aegaeon.organization_authority_events(id)"},{"name":"organization_authority_outbox_event_id_not_null","deferred":false,"relation":"organization_authority_outbox","validated":true,"deferrable":false,"definition":"NOT NULL event_id"},{"name":"organization_authority_outbox_pkey","deferred":false,"relation":"organization_authority_outbox","validated":true,"deferrable":false,"definition":"PRIMARY KEY (event_id)"},{"name":"organization_authority_receipts_actor_id_not_null","deferred":false,"relation":"organization_authority_receipts","validated":true,"deferrable":false,"definition":"NOT NULL actor_id"},{"name":"organization_authority_receipts_actor_kind_check","deferred":false,"relation":"organization_authority_receipts","validated":true,"deferrable":false,"definition":"CHECK ((actor_kind = ANY (ARRAY['operator'::text, 'member'::text])))"},{"name":"organization_authority_receipts_actor_kind_not_null","deferred":false,"relation":"organization_authority_receipts","validated":true,"deferrable":false,"definition":"NOT NULL actor_kind"},{"name":"organization_authority_receipts_client_id_not_null","deferred":false,"relation":"organization_authority_receipts","validated":true,"deferrable":false,"definition":"NOT NULL client_id"},{"name":"organization_authority_receipts_client_registration_id_not_null","deferred":false,"relation":"organization_authority_receipts","validated":true,"deferrable":false,"definition":"NOT NULL client_registration_id"},{"name":"organization_authority_receipts_created_at_not_null","deferred":false,"relation":"organization_authority_receipts","validated":true,"deferrable":false,"definition":"NOT NULL created_at"},{"name":"organization_authority_receipts_domain_id_not_null","deferred":false,"relation":"organization_authority_receipts","validated":true,"deferrable":false,"definition":"NOT NULL domain_id"},{"name":"organization_authority_receipts_environment_id_domain_id_fkey","deferred":false,"relation":"organization_authority_receipts","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id, domain_id) REFERENCES aegaeon.authorization_domains(environment_id, id)"},{"name":"organization_authority_receipts_environment_id_not_null","deferred":false,"relation":"organization_authority_receipts","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"organization_authority_receipts_idempotency_key_check","deferred":false,"relation":"organization_authority_receipts","validated":true,"deferrable":false,"definition":"CHECK (((octet_length(idempotency_key) >= 1) AND (octet_length(idempotency_key) <= 128)))"},{"name":"organization_authority_receipts_idempotency_key_not_null","deferred":false,"relation":"organization_authority_receipts","validated":true,"deferrable":false,"definition":"NOT NULL idempotency_key"},{"name":"organization_authority_receipts_operation_not_null","deferred":false,"relation":"organization_authority_receipts","validated":true,"deferrable":false,"definition":"NOT NULL operation"},{"name":"organization_authority_receipts_pkey","deferred":false,"relation":"organization_authority_receipts","validated":true,"deferrable":false,"definition":"PRIMARY KEY (environment_id, domain_id, actor_id, actor_kind, client_id, client_registration_id, operation, idempotency_key)"},{"name":"organization_authority_receipts_request_digest_check","deferred":false,"relation":"organization_authority_receipts","validated":true,"deferrable":false,"definition":"CHECK ((octet_length(request_digest) = 32))"},{"name":"organization_authority_receipts_request_digest_not_null","deferred":false,"relation":"organization_authority_receipts","validated":true,"deferrable":false,"definition":"NOT NULL request_digest"},{"name":"organization_authority_receipts_result_not_null","deferred":false,"relation":"organization_authority_receipts","validated":true,"deferrable":false,"definition":"NOT NULL result"},{"name":"organization_client_binding_registration","deferred":false,"relation":"organization_client_bindings","validated":true,"deferrable":false,"definition":"UNIQUE (environment_id, domain_id, client_registration_id)"},{"name":"organization_client_bindings_active_not_null","deferred":false,"relation":"organization_client_bindings","validated":true,"deferrable":false,"definition":"NOT NULL active"},{"name":"organization_client_bindings_client_identifier_check","deferred":false,"relation":"organization_client_bindings","validated":true,"deferrable":false,"definition":"CHECK (((octet_length(client_identifier) >= 1) AND (octet_length(client_identifier) <= 255)))"},{"name":"organization_client_bindings_client_identifier_not_null","deferred":false,"relation":"organization_client_bindings","validated":true,"deferrable":false,"definition":"NOT NULL client_identifier"},{"name":"organization_client_bindings_client_registration_id_not_null","deferred":false,"relation":"organization_client_bindings","validated":true,"deferrable":false,"definition":"NOT NULL client_registration_id"},{"name":"organization_client_bindings_created_at_not_null","deferred":false,"relation":"organization_client_bindings","validated":true,"deferrable":false,"definition":"NOT NULL created_at"},{"name":"organization_client_bindings_domain_id_not_null","deferred":false,"relation":"organization_client_bindings","validated":true,"deferrable":false,"definition":"NOT NULL domain_id"},{"name":"organization_client_bindings_environment_id_domain_id_fkey","deferred":false,"relation":"organization_client_bindings","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id, domain_id) REFERENCES aegaeon.authorization_domains(environment_id, id)"},{"name":"organization_client_bindings_environment_id_not_null","deferred":false,"relation":"organization_client_bindings","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"organization_client_bindings_id_not_null","deferred":false,"relation":"organization_client_bindings","validated":true,"deferrable":false,"definition":"NOT NULL id"},{"name":"organization_client_bindings_pkey","deferred":false,"relation":"organization_client_bindings","validated":true,"deferrable":false,"definition":"PRIMARY KEY (id)"},{"name":"organization_client_bindings_revision_check","deferred":false,"relation":"organization_client_bindings","validated":true,"deferrable":false,"definition":"CHECK ((revision > 0))"},{"name":"organization_client_bindings_revision_not_null","deferred":false,"relation":"organization_client_bindings","validated":true,"deferrable":false,"definition":"NOT NULL revision"},{"name":"organization_client_bindings_targets_check","deferred":false,"relation":"organization_client_bindings","validated":true,"deferrable":false,"definition":"CHECK (((jsonb_typeof(targets) = 'array'::text) AND ((jsonb_array_length(targets) >= 1) AND (jsonb_array_length(targets) <= 32)) AND (octet_length((targets)::text) <= 65536)))"},{"name":"organization_client_bindings_targets_not_null","deferred":false,"relation":"organization_client_bindings","validated":true,"deferrable":false,"definition":"NOT NULL targets"},{"name":"organization_creation_receipt_environment_id_kind_selector__key","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"UNIQUE (environment_id, kind, selector_sha256)"},{"name":"organization_creation_receipts_actor_sha256_check","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"CHECK (((octet_length(actor_sha256) = 64) AND (actor_sha256 ~ '^[0-9a-f]{64}$'::text)))"},{"name":"organization_creation_receipts_actor_sha256_not_null","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"NOT NULL actor_sha256"},{"name":"organization_creation_receipts_attempt_check","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"CHECK (((attempt >= 1) AND (attempt <= 32)))"},{"name":"organization_creation_receipts_attempt_not_null","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"NOT NULL attempt"},{"name":"organization_creation_receipts_environment_id_not_null","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"organization_creation_receipts_epoch_check","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"CHECK ((epoch <> '00000000-0000-0000-0000-000000000000'::uuid))"},{"name":"organization_creation_receipts_epoch_not_null","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"NOT NULL epoch"},{"name":"organization_creation_receipts_identity_revision_check","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"CHECK (((identity_revision > 0) AND (identity_revision < '9223372036854775807'::bigint)))"},{"name":"organization_creation_receipts_identity_revision_not_null","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"NOT NULL identity_revision"},{"name":"organization_creation_receipts_kind_check","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"CHECK ((kind = ANY (ARRAY['management_create'::text, 'management_invite'::text, 'management_csv'::text, 'registration'::text, 'upstream'::text])))"},{"name":"organization_creation_receipts_kind_not_null","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"NOT NULL kind"},{"name":"organization_creation_receipts_operation_id_check","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"CHECK ((operation_id <> '00000000-0000-0000-0000-000000000000'::uuid))"},{"name":"organization_creation_receipts_operation_id_not_null","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"NOT NULL operation_id"},{"name":"organization_creation_receipts_owner_id_check","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"CHECK ((owner_id <> '00000000-0000-0000-0000-000000000000'::uuid))"},{"name":"organization_creation_receipts_owner_id_environment_id_fkey","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"FOREIGN KEY (owner_id, environment_id) REFERENCES aegaeon.end_user_identity_owners(owner_id, environment_id)"},{"name":"organization_creation_receipts_owner_id_key","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"UNIQUE (owner_id)"},{"name":"organization_creation_receipts_owner_id_not_null","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"NOT NULL owner_id"},{"name":"organization_creation_receipts_payload_sha256_check","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"CHECK (((octet_length(payload_sha256) = 64) AND (payload_sha256 ~ '^[0-9a-f]{64}$'::text)))"},{"name":"organization_creation_receipts_payload_sha256_not_null","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"NOT NULL payload_sha256"},{"name":"organization_creation_receipts_pkey","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"PRIMARY KEY (environment_id, operation_id)"},{"name":"organization_creation_receipts_receipt_sha256_check","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"CHECK ((octet_length(receipt_sha256) = 32))"},{"name":"organization_creation_receipts_receipt_sha256_not_null","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"NOT NULL receipt_sha256"},{"name":"organization_creation_receipts_recorded_at_not_null","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"NOT NULL recorded_at"},{"name":"organization_creation_receipts_selector_sha256_check","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"CHECK (((octet_length(selector_sha256) = 64) AND (selector_sha256 ~ '^[0-9a-f]{64}$'::text)))"},{"name":"organization_creation_receipts_selector_sha256_not_null","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"NOT NULL selector_sha256"},{"name":"organization_creation_receipts_subject_check","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"CHECK (aegaeon.subject_ownership_valid_subject(subject))"},{"name":"organization_creation_receipts_subject_not_null","deferred":false,"relation":"organization_creation_receipts","validated":true,"deferrable":false,"definition":"NOT NULL subject"},{"name":"organization_identity_invitation_revision_positive","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"CHECK ((invitation_delivery_revision > 0))"},{"name":"organization_identity_reque_invitation_delivery_revisi_not_null","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"NOT NULL invitation_delivery_revision"},{"name":"organization_identity_request_environment_id_domain_id_inv_fkey","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id, domain_id, invitation_id) REFERENCES aegaeon.organization_invitations(environment_id, domain_id, id)"},{"name":"organization_identity_request_environment_id_domain_id_invi_key","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"UNIQUE (environment_id, domain_id, invitation_id, request_key)"},{"name":"organization_identity_requests_capability_hash_check","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"CHECK ((octet_length(capability_hash) = 32))"},{"name":"organization_identity_requests_check","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"CHECK (((expires_at > issued_at) AND ((expires_at - issued_at) <= 600)))"},{"name":"organization_identity_requests_check1","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"CHECK (((target_user_id IS NULL) = (target_identity_revision IS NULL)))"},{"name":"organization_identity_requests_check2","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"CHECK ((((state = 'pending'::text) AND (result IS NULL)) OR ((state = 'completed'::text) AND (jsonb_typeof(result) = 'object'::text))))"},{"name":"organization_identity_requests_check3","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"CHECK ((((delivery_revision = 0) AND (delivered_at IS NULL) AND (capability_hash IS NULL) AND (delivery_outcome = 'unclaimed'::text)) OR ((delivery_revision > 0) AND (delivered_at IS NOT NULL) AND (capability_hash IS NOT NULL) AND (delivery_outcome <> 'unclaimed'::text))))"},{"name":"organization_identity_requests_delivery_outcome_check","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"CHECK ((delivery_outcome = ANY (ARRAY['unclaimed'::text, 'uncertain'::text, 'acknowledged'::text, 'rejected'::text])))"},{"name":"organization_identity_requests_delivery_outcome_not_null","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"NOT NULL delivery_outcome"},{"name":"organization_identity_requests_delivery_revision_check","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"CHECK (((delivery_revision >= 0) AND (delivery_revision <= 5)))"},{"name":"organization_identity_requests_delivery_revision_not_null","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"NOT NULL delivery_revision"},{"name":"organization_identity_requests_domain_id_not_null","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"NOT NULL domain_id"},{"name":"organization_identity_requests_environment_id_not_null","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"organization_identity_requests_expires_at_not_null","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"NOT NULL expires_at"},{"name":"organization_identity_requests_id_not_null","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"NOT NULL id"},{"name":"organization_identity_requests_invitation_id_not_null","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"NOT NULL invitation_id"},{"name":"organization_identity_requests_issued_at_check","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"CHECK ((issued_at >= 0))"},{"name":"organization_identity_requests_issued_at_not_null","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"NOT NULL issued_at"},{"name":"organization_identity_requests_pkey","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"PRIMARY KEY (id)"},{"name":"organization_identity_requests_policy_revision_check","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"CHECK ((policy_revision > 0))"},{"name":"organization_identity_requests_policy_revision_not_null","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"NOT NULL policy_revision"},{"name":"organization_identity_requests_purpose_check","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"CHECK ((purpose = ANY (ARRAY['registration'::text, 'password_recovery'::text])))"},{"name":"organization_identity_requests_purpose_not_null","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"NOT NULL purpose"},{"name":"organization_identity_requests_request_digest_check","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"CHECK ((octet_length(request_digest) = 32))"},{"name":"organization_identity_requests_request_digest_not_null","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"NOT NULL request_digest"},{"name":"organization_identity_requests_request_key_check","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"CHECK (((octet_length(request_key) >= 1) AND (octet_length(request_key) <= 128)))"},{"name":"organization_identity_requests_request_key_not_null","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"NOT NULL request_key"},{"name":"organization_identity_requests_state_check","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"CHECK ((state = ANY (ARRAY['pending'::text, 'completed'::text])))"},{"name":"organization_identity_requests_state_not_null","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"NOT NULL state"},{"name":"organization_identity_requests_target_identity_revision_check","deferred":false,"relation":"organization_identity_requests","validated":true,"deferrable":false,"definition":"CHECK ((target_identity_revision > 0))"},{"name":"organization_import_operations_created_at_not_null","deferred":false,"relation":"organization_import_operations","validated":true,"deferrable":false,"definition":"NOT NULL created_at"},{"name":"organization_import_operations_domain_id_not_null","deferred":false,"relation":"organization_import_operations","validated":true,"deferrable":false,"definition":"NOT NULL domain_id"},{"name":"organization_import_operations_environment_id_domain_id_key","deferred":false,"relation":"organization_import_operations","validated":true,"deferrable":false,"definition":"UNIQUE (environment_id, domain_id)"},{"name":"organization_import_operations_environment_id_fkey","deferred":false,"relation":"organization_import_operations","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id)"},{"name":"organization_import_operations_environment_id_not_null","deferred":false,"relation":"organization_import_operations","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"organization_import_operations_id_check","deferred":false,"relation":"organization_import_operations","validated":true,"deferrable":false,"definition":"CHECK ((id <> '00000000-0000-0000-0000-000000000000'::uuid))"},{"name":"organization_import_operations_id_not_null","deferred":false,"relation":"organization_import_operations","validated":true,"deferrable":false,"definition":"NOT NULL id"},{"name":"organization_import_operations_maintenance_actor_not_null","deferred":false,"relation":"organization_import_operations","validated":true,"deferrable":false,"definition":"NOT NULL maintenance_actor"},{"name":"organization_import_operations_pkey","deferred":false,"relation":"organization_import_operations","validated":true,"deferrable":false,"definition":"PRIMARY KEY (id)"},{"name":"organization_import_operations_receipt_check","deferred":false,"relation":"organization_import_operations","validated":true,"deferrable":false,"definition":"CHECK (((jsonb_typeof(receipt) = 'object'::text) AND (octet_length((receipt)::text) <= 32768)))"},{"name":"organization_import_operations_receipt_not_null","deferred":false,"relation":"organization_import_operations","validated":true,"deferrable":false,"definition":"NOT NULL receipt"},{"name":"organization_import_operations_session_actor_not_null","deferred":false,"relation":"organization_import_operations","validated":true,"deferrable":false,"definition":"NOT NULL session_actor"},{"name":"organization_import_operations_source_enabled_not_null","deferred":false,"relation":"organization_import_operations","validated":true,"deferrable":false,"definition":"NOT NULL source_enabled"},{"name":"organization_import_operations_source_sha256_check","deferred":false,"relation":"organization_import_operations","validated":true,"deferrable":false,"definition":"CHECK ((source_sha256 ~ '^[0-9a-f]{64}$'::text))"},{"name":"organization_import_operations_source_sha256_not_null","deferred":false,"relation":"organization_import_operations","validated":true,"deferrable":false,"definition":"NOT NULL source_sha256"},{"name":"organization_import_operations_state_check","deferred":false,"relation":"organization_import_operations","validated":true,"deferrable":false,"definition":"CHECK ((state = ANY (ARRAY['writing'::text, 'prepared'::text])))"},{"name":"organization_import_operations_state_not_null","deferred":false,"relation":"organization_import_operations","validated":true,"deferrable":false,"definition":"NOT NULL state"},{"name":"organization_challenge_delivery_state","deferred":false,"relation":"organization_invitation_challenges","validated":true,"deferrable":false,"definition":"CHECK (((delivery_revision = 0) = (delivery_outcome = 'unclaimed'::text)))"},{"name":"organization_invitation_cha_invitation_delivery_revisi_not_null","deferred":false,"relation":"organization_invitation_challenges","validated":true,"deferrable":false,"definition":"NOT NULL invitation_delivery_revision"},{"name":"organization_invitation_chal_invitation_delivery_revision_check","deferred":false,"relation":"organization_invitation_challenges","validated":true,"deferrable":false,"definition":"CHECK (((invitation_delivery_revision >= 1) AND (invitation_delivery_revision <= 5)))"},{"name":"organization_invitation_chall_environment_id_domain_id_inv_fkey","deferred":false,"relation":"organization_invitation_challenges","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id, domain_id, invitation_id) REFERENCES aegaeon.organization_invitations(environment_id, domain_id, id)"},{"name":"organization_invitation_chall_environment_id_domain_id_invi_key","deferred":false,"relation":"organization_invitation_challenges","validated":true,"deferrable":false,"definition":"UNIQUE (environment_id, domain_id, invitation_id, request_key)"},{"name":"organization_invitation_challenges_capability_hash_check","deferred":false,"relation":"organization_invitation_challenges","validated":true,"deferrable":false,"definition":"CHECK ((octet_length(capability_hash) = 32))"},{"name":"organization_invitation_challenges_check","deferred":false,"relation":"organization_invitation_challenges","validated":true,"deferrable":false,"definition":"CHECK (((expires_at > issued_at) AND (((expires_at)::numeric - (issued_at)::numeric) <= (300)::numeric)))"},{"name":"organization_invitation_challenges_check1","deferred":false,"relation":"organization_invitation_challenges","validated":true,"deferrable":false,"definition":"CHECK ((((delivery_revision = 0) AND (delivered_at IS NULL) AND (capability_hash IS NULL)) OR ((delivery_revision > 0) AND (delivered_at IS NOT NULL) AND (capability_hash IS NOT NULL))))"},{"name":"organization_invitation_challenges_delivery_outcome_check","deferred":false,"relation":"organization_invitation_challenges","validated":true,"deferrable":false,"definition":"CHECK ((delivery_outcome = ANY (ARRAY['unclaimed'::text, 'uncertain'::text, 'acknowledged'::text, 'rejected'::text])))"},{"name":"organization_invitation_challenges_delivery_outcome_not_null","deferred":false,"relation":"organization_invitation_challenges","validated":true,"deferrable":false,"definition":"NOT NULL delivery_outcome"},{"name":"organization_invitation_challenges_delivery_revision_check","deferred":false,"relation":"organization_invitation_challenges","validated":true,"deferrable":false,"definition":"CHECK (((delivery_revision >= 0) AND (delivery_revision <= 5)))"},{"name":"organization_invitation_challenges_delivery_revision_not_null","deferred":false,"relation":"organization_invitation_challenges","validated":true,"deferrable":false,"definition":"NOT NULL delivery_revision"},{"name":"organization_invitation_challenges_domain_id_not_null","deferred":false,"relation":"organization_invitation_challenges","validated":true,"deferrable":false,"definition":"NOT NULL domain_id"},{"name":"organization_invitation_challenges_environment_id_not_null","deferred":false,"relation":"organization_invitation_challenges","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"organization_invitation_challenges_expires_at_not_null","deferred":false,"relation":"organization_invitation_challenges","validated":true,"deferrable":false,"definition":"NOT NULL expires_at"},{"name":"organization_invitation_challenges_id_not_null","deferred":false,"relation":"organization_invitation_challenges","validated":true,"deferrable":false,"definition":"NOT NULL id"},{"name":"organization_invitation_challenges_invitation_id_not_null","deferred":false,"relation":"organization_invitation_challenges","validated":true,"deferrable":false,"definition":"NOT NULL invitation_id"},{"name":"organization_invitation_challenges_issued_at_check","deferred":false,"relation":"organization_invitation_challenges","validated":true,"deferrable":false,"definition":"CHECK ((issued_at >= 0))"},{"name":"organization_invitation_challenges_issued_at_not_null","deferred":false,"relation":"organization_invitation_challenges","validated":true,"deferrable":false,"definition":"NOT NULL issued_at"},{"name":"organization_invitation_challenges_pkey","deferred":false,"relation":"organization_invitation_challenges","validated":true,"deferrable":false,"definition":"PRIMARY KEY (id)"},{"name":"organization_invitation_challenges_recipient_binding_check","deferred":false,"relation":"organization_invitation_challenges","validated":true,"deferrable":false,"definition":"CHECK (((jsonb_typeof(recipient_binding) = 'object'::text) AND (octet_length((recipient_binding)::text) <= 4096)))"},{"name":"organization_invitation_challenges_recipient_binding_not_null","deferred":false,"relation":"organization_invitation_challenges","validated":true,"deferrable":false,"definition":"NOT NULL recipient_binding"},{"name":"organization_invitation_challenges_request_key_check","deferred":false,"relation":"organization_invitation_challenges","validated":true,"deferrable":false,"definition":"CHECK (((octet_length(request_key) >= 1) AND (octet_length(request_key) <= 128)))"},{"name":"organization_invitation_challenges_request_key_not_null","deferred":false,"relation":"organization_invitation_challenges","validated":true,"deferrable":false,"definition":"NOT NULL request_key"},{"name":"organization_invitation_delivery_state","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"CHECK (((delivery_revision = 0) = (delivery_outcome = 'unclaimed'::text)))"},{"name":"organization_invitations_authority_check","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"CHECK (((jsonb_typeof(authority) = 'object'::text) AND (octet_length((authority)::text) <= 65536)))"},{"name":"organization_invitations_authority_not_null","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"NOT NULL authority"},{"name":"organization_invitations_capability_hash_check","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"CHECK ((octet_length(capability_hash) = 32))"},{"name":"organization_invitations_check","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"CHECK (((expires_at > issued_at) AND ((((expires_at)::numeric - (issued_at)::numeric) >= (60)::numeric) AND (((expires_at)::numeric - (issued_at)::numeric) <= (86400)::numeric))))"},{"name":"organization_invitations_check1","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"CHECK ((((delivery_revision = 0) AND (delivered_at IS NULL) AND (capability_hash IS NULL)) OR ((delivery_revision > 0) AND (delivered_at IS NOT NULL) AND (capability_hash IS NOT NULL))))"},{"name":"organization_invitations_check2","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"CHECK (((state = 'accepted'::text) = ((accepted_challenge_id IS NOT NULL) AND (result IS NOT NULL))))"},{"name":"organization_invitations_delivery_outcome_check","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"CHECK ((delivery_outcome = ANY (ARRAY['unclaimed'::text, 'uncertain'::text, 'acknowledged'::text, 'rejected'::text])))"},{"name":"organization_invitations_delivery_outcome_not_null","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"NOT NULL delivery_outcome"},{"name":"organization_invitations_delivery_revision_check","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"CHECK (((delivery_revision >= 0) AND (delivery_revision <= 5)))"},{"name":"organization_invitations_delivery_revision_not_null","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"NOT NULL delivery_revision"},{"name":"organization_invitations_domain_id_not_null","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"NOT NULL domain_id"},{"name":"organization_invitations_environment_id_domain_id_id_key","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"UNIQUE (environment_id, domain_id, id)"},{"name":"organization_invitations_environment_id_domain_id_organiza_fkey","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id, domain_id, organization_id) REFERENCES aegaeon.application_organizations(environment_id, domain_id, id)"},{"name":"organization_invitations_environment_id_not_null","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"organization_invitations_expires_at_not_null","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"NOT NULL expires_at"},{"name":"organization_invitations_id_not_null","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"NOT NULL id"},{"name":"organization_invitations_issued_at_check","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"CHECK ((issued_at >= 0))"},{"name":"organization_invitations_issued_at_not_null","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"NOT NULL issued_at"},{"name":"organization_invitations_organization_id_not_null","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"NOT NULL organization_id"},{"name":"organization_invitations_pkey","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"PRIMARY KEY (id)"},{"name":"organization_invitations_recipient_check","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"CHECK (((octet_length(recipient) >= 3) AND (octet_length(recipient) <= 254)))"},{"name":"organization_invitations_recipient_not_null","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"NOT NULL recipient"},{"name":"organization_invitations_result_check","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"CHECK (((jsonb_typeof(result) = 'object'::text) AND (octet_length((result)::text) <= 16384)))"},{"name":"organization_invitations_revision_check","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"CHECK ((revision > 0))"},{"name":"organization_invitations_revision_not_null","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"NOT NULL revision"},{"name":"organization_invitations_state_check","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"CHECK ((state = ANY (ARRAY['pending'::text, 'revoked'::text, 'accepted'::text])))"},{"name":"organization_invitations_state_not_null","deferred":false,"relation":"organization_invitations","validated":true,"deferrable":false,"definition":"NOT NULL state"},{"name":"organization_memberships_domain_id_not_null","deferred":false,"relation":"organization_memberships","validated":true,"deferrable":false,"definition":"NOT NULL domain_id"},{"name":"organization_memberships_end_user_id_environment_id_fkey","deferred":false,"relation":"organization_memberships","validated":true,"deferrable":false,"definition":"FOREIGN KEY (end_user_id, environment_id) REFERENCES aegaeon.end_user_identity_owners(owner_id, environment_id)"},{"name":"organization_memberships_end_user_id_not_null","deferred":false,"relation":"organization_memberships","validated":true,"deferrable":false,"definition":"NOT NULL end_user_id"},{"name":"organization_memberships_environment_id_domain_id_organiza_fkey","deferred":false,"relation":"organization_memberships","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id, domain_id, organization_id) REFERENCES aegaeon.application_organizations(environment_id, domain_id, id)"},{"name":"organization_memberships_environment_id_not_null","deferred":false,"relation":"organization_memberships","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"organization_memberships_grant_generation_check","deferred":false,"relation":"organization_memberships","validated":true,"deferrable":false,"definition":"CHECK ((grant_generation > 0))"},{"name":"organization_memberships_grant_generation_not_null","deferred":false,"relation":"organization_memberships","validated":true,"deferrable":false,"definition":"NOT NULL grant_generation"},{"name":"organization_memberships_incarnation_not_null","deferred":false,"relation":"organization_memberships","validated":true,"deferrable":false,"definition":"NOT NULL incarnation"},{"name":"organization_memberships_organization_id_not_null1","deferred":false,"relation":"organization_memberships","validated":true,"deferrable":false,"definition":"NOT NULL organization_id"},{"name":"organization_memberships_pkey","deferred":false,"relation":"organization_memberships","validated":true,"deferrable":false,"definition":"PRIMARY KEY (environment_id, domain_id, organization_id, end_user_id)"},{"name":"organization_memberships_revision_check","deferred":false,"relation":"organization_memberships","validated":true,"deferrable":false,"definition":"CHECK ((revision > 0))"},{"name":"organization_memberships_revision_not_null","deferred":false,"relation":"organization_memberships","validated":true,"deferrable":false,"definition":"NOT NULL revision"},{"name":"organization_memberships_roles_check","deferred":false,"relation":"organization_memberships","validated":true,"deferrable":false,"definition":"CHECK (((jsonb_typeof(roles) = 'array'::text) AND (jsonb_array_length(roles) <= 64)))"},{"name":"organization_memberships_roles_not_null","deferred":false,"relation":"organization_memberships","validated":true,"deferrable":false,"definition":"NOT NULL roles"},{"name":"organization_memberships_state_check","deferred":false,"relation":"organization_memberships","validated":true,"deferrable":false,"definition":"CHECK ((state = ANY (ARRAY['invited'::text, 'active'::text, 'suspended'::text, 'removed'::text])))"},{"name":"organization_memberships_state_not_null","deferred":false,"relation":"organization_memberships","validated":true,"deferrable":false,"definition":"NOT NULL state"},{"name":"organization_operator_grants_active_not_null","deferred":false,"relation":"organization_operator_grants","validated":true,"deferrable":false,"definition":"NOT NULL active"},{"name":"organization_operator_grants_administrator_id_fkey","deferred":false,"relation":"organization_operator_grants","validated":true,"deferrable":false,"definition":"FOREIGN KEY (administrator_id) REFERENCES aegaeon.administrators(id)"},{"name":"organization_operator_grants_administrator_id_not_null","deferred":false,"relation":"organization_operator_grants","validated":true,"deferrable":false,"definition":"NOT NULL administrator_id"},{"name":"organization_operator_grants_capabilities_check","deferred":false,"relation":"organization_operator_grants","validated":true,"deferrable":false,"definition":"CHECK (((jsonb_typeof(capabilities) = 'array'::text) AND ((jsonb_array_length(capabilities) >= 1) AND (jsonb_array_length(capabilities) <= 5)) AND (capabilities <@ '[\"configure\", \"provision\", \"reconcile\", \"export\", \"support\"]'::jsonb)))"},{"name":"organization_operator_grants_capabilities_not_null","deferred":false,"relation":"organization_operator_grants","validated":true,"deferrable":false,"definition":"NOT NULL capabilities"},{"name":"organization_operator_grants_created_at_not_null","deferred":false,"relation":"organization_operator_grants","validated":true,"deferrable":false,"definition":"NOT NULL created_at"},{"name":"organization_operator_grants_domain_id_not_null","deferred":false,"relation":"organization_operator_grants","validated":true,"deferrable":false,"definition":"NOT NULL domain_id"},{"name":"organization_operator_grants_environment_id_domain_id_admin_key","deferred":false,"relation":"organization_operator_grants","validated":true,"deferrable":false,"definition":"UNIQUE (environment_id, domain_id, administrator_id)"},{"name":"organization_operator_grants_environment_id_domain_id_fkey","deferred":false,"relation":"organization_operator_grants","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id, domain_id) REFERENCES aegaeon.authorization_domains(environment_id, id)"},{"name":"organization_operator_grants_environment_id_not_null","deferred":false,"relation":"organization_operator_grants","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"organization_operator_grants_id_not_null","deferred":false,"relation":"organization_operator_grants","validated":true,"deferrable":false,"definition":"NOT NULL id"},{"name":"organization_operator_grants_pkey","deferred":false,"relation":"organization_operator_grants","validated":true,"deferrable":false,"definition":"PRIMARY KEY (id)"},{"name":"organization_operator_grants_revision_check","deferred":false,"relation":"organization_operator_grants","validated":true,"deferrable":false,"definition":"CHECK ((revision > 0))"},{"name":"organization_operator_grants_revision_not_null","deferred":false,"relation":"organization_operator_grants","validated":true,"deferrable":false,"definition":"NOT NULL revision"},{"name":"organization_role_definitions_assignable_roles_not_null","deferred":false,"relation":"organization_role_definitions","validated":true,"deferrable":false,"definition":"NOT NULL assignable_roles"},{"name":"organization_role_definitions_check","deferred":false,"relation":"organization_role_definitions","validated":true,"deferrable":false,"definition":"CHECK (((jsonb_typeof(assignable_roles) = 'array'::text) AND (jsonb_array_length(assignable_roles) <= 64) AND (manages_members OR (assignable_roles = '[]'::jsonb))))"},{"name":"organization_role_definitions_domain_id_not_null","deferred":false,"relation":"organization_role_definitions","validated":true,"deferrable":false,"definition":"NOT NULL domain_id"},{"name":"organization_role_definitions_environment_id_domain_id_fkey","deferred":false,"relation":"organization_role_definitions","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id, domain_id) REFERENCES aegaeon.authorization_domains(environment_id, id)"},{"name":"organization_role_definitions_environment_id_not_null","deferred":false,"relation":"organization_role_definitions","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"organization_role_definitions_manages_members_not_null","deferred":false,"relation":"organization_role_definitions","validated":true,"deferrable":false,"definition":"NOT NULL manages_members"},{"name":"organization_role_definitions_pkey","deferred":false,"relation":"organization_role_definitions","validated":true,"deferrable":false,"definition":"PRIMARY KEY (environment_id, domain_id, role_key)"},{"name":"organization_role_definitions_privileges_check","deferred":false,"relation":"organization_role_definitions","validated":true,"deferrable":false,"definition":"CHECK (((jsonb_typeof(privileges) = 'array'::text) AND ((jsonb_array_length(privileges) >= 1) AND (jsonb_array_length(privileges) <= 256))))"},{"name":"organization_role_definitions_privileges_not_null","deferred":false,"relation":"organization_role_definitions","validated":true,"deferrable":false,"definition":"NOT NULL privileges"},{"name":"organization_role_definitions_role_key_check","deferred":false,"relation":"organization_role_definitions","validated":true,"deferrable":false,"definition":"CHECK ((role_key ~ '^[A-Za-z0-9._:-]{1,128}$'::text))"},{"name":"organization_role_definitions_role_key_not_null","deferred":false,"relation":"organization_role_definitions","validated":true,"deferrable":false,"definition":"NOT NULL role_key"},{"name":"organization_role_definitions_version_check","deferred":false,"relation":"organization_role_definitions","validated":true,"deferrable":false,"definition":"CHECK ((version > 0))"},{"name":"organization_role_definitions_version_not_null","deferred":false,"relation":"organization_role_definitions","validated":true,"deferrable":false,"definition":"NOT NULL version"},{"name":"subject_history_restoration_pages_after_sequence_check","deferred":false,"relation":"subject_history_restoration_pages","validated":true,"deferrable":false,"definition":"CHECK (((after_sequence >= 0) AND (after_sequence <= 999999)))"},{"name":"subject_history_restoration_pages_after_sequence_not_null","deferred":false,"relation":"subject_history_restoration_pages","validated":true,"deferrable":false,"definition":"NOT NULL after_sequence"},{"name":"subject_history_restoration_pages_check","deferred":false,"relation":"subject_history_restoration_pages","validated":true,"deferrable":false,"definition":"CHECK (((after_sequence + entry_count) <= 1000000))"},{"name":"subject_history_restoration_pages_digest_check","deferred":false,"relation":"subject_history_restoration_pages","validated":true,"deferrable":false,"definition":"CHECK ((octet_length(digest) = 32))"},{"name":"subject_history_restoration_pages_digest_not_null","deferred":false,"relation":"subject_history_restoration_pages","validated":true,"deferrable":false,"definition":"NOT NULL digest"},{"name":"subject_history_restoration_pages_entry_count_check","deferred":false,"relation":"subject_history_restoration_pages","validated":true,"deferrable":false,"definition":"CHECK (((entry_count >= 1) AND (entry_count <= 256)))"},{"name":"subject_history_restoration_pages_entry_count_not_null","deferred":false,"relation":"subject_history_restoration_pages","validated":true,"deferrable":false,"definition":"NOT NULL entry_count"},{"name":"subject_history_restoration_pages_input_check","deferred":false,"relation":"subject_history_restoration_pages","validated":true,"deferrable":false,"definition":"CHECK (((jsonb_typeof(input) = 'object'::text) AND (octet_length((input)::text) <= 1048576)))"},{"name":"subject_history_restoration_pages_input_not_null","deferred":false,"relation":"subject_history_restoration_pages","validated":true,"deferrable":false,"definition":"NOT NULL input"},{"name":"subject_history_restoration_pages_operation_id_fkey","deferred":false,"relation":"subject_history_restoration_pages","validated":true,"deferrable":false,"definition":"FOREIGN KEY (operation_id) REFERENCES aegaeon.subject_history_restorations(operation_id)"},{"name":"subject_history_restoration_pages_operation_id_not_null","deferred":false,"relation":"subject_history_restoration_pages","validated":true,"deferrable":false,"definition":"NOT NULL operation_id"},{"name":"subject_history_restoration_pages_pkey","deferred":false,"relation":"subject_history_restoration_pages","validated":true,"deferrable":false,"definition":"PRIMARY KEY (operation_id, after_sequence)"},{"name":"subject_history_restoration_pages_recorded_at_not_null","deferred":false,"relation":"subject_history_restoration_pages","validated":true,"deferrable":false,"definition":"NOT NULL recorded_at"},{"name":"subject_history_restoration_pages_session_actor_not_null","deferred":false,"relation":"subject_history_restoration_pages","validated":true,"deferrable":false,"definition":"NOT NULL session_actor"},{"name":"subject_history_restorations_environment_id_fkey","deferred":false,"relation":"subject_history_restorations","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id) REFERENCES aegaeon.subject_ownership_namespaces(environment_id)"},{"name":"subject_history_restorations_environment_id_not_null","deferred":false,"relation":"subject_history_restorations","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"subject_history_restorations_operation_id_check","deferred":false,"relation":"subject_history_restorations","validated":true,"deferrable":false,"definition":"CHECK ((operation_id <> '00000000-0000-0000-0000-000000000000'::uuid))"},{"name":"subject_history_restorations_operation_id_not_null","deferred":false,"relation":"subject_history_restorations","validated":true,"deferrable":false,"definition":"NOT NULL operation_id"},{"name":"subject_history_restorations_pkey","deferred":false,"relation":"subject_history_restorations","validated":true,"deferrable":false,"definition":"PRIMARY KEY (operation_id)"},{"name":"subject_history_restorations_recorded_at_not_null","deferred":false,"relation":"subject_history_restorations","validated":true,"deferrable":false,"definition":"NOT NULL recorded_at"},{"name":"subject_history_restorations_session_actor_not_null","deferred":false,"relation":"subject_history_restorations","validated":true,"deferrable":false,"definition":"NOT NULL session_actor"},{"name":"subject_history_restorations_source_check","deferred":false,"relation":"subject_history_restorations","validated":true,"deferrable":false,"definition":"CHECK (((jsonb_typeof(source) = 'object'::text) AND (octet_length((source)::text) <= 4096)))"},{"name":"subject_history_restorations_source_not_null","deferred":false,"relation":"subject_history_restorations","validated":true,"deferrable":false,"definition":"NOT NULL source"},{"name":"subject_ownership_adoptions_contract_version_check","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"CHECK ((contract_version = 1))"},{"name":"subject_ownership_adoptions_contract_version_not_null","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"NOT NULL contract_version"},{"name":"subject_ownership_adoptions_definer_actor_not_null","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"NOT NULL definer_actor"},{"name":"subject_ownership_adoptions_effective_actor_not_null","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"NOT NULL effective_actor"},{"name":"subject_ownership_adoptions_environment_id_kind_fkey","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id, kind) REFERENCES aegaeon.subject_ownership_namespaces(environment_id, origin) ON DELETE RESTRICT"},{"name":"subject_ownership_adoptions_environment_id_not_null","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"subject_ownership_adoptions_kind_not_null","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"NOT NULL kind"},{"name":"subject_ownership_adoptions_pkey","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"PRIMARY KEY (environment_id)"},{"name":"subject_ownership_adoptions_receipt_id_key","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"UNIQUE (receipt_id)"},{"name":"subject_ownership_adoptions_receipt_id_not_null","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"NOT NULL receipt_id"},{"name":"subject_ownership_adoptions_recorded_at_not_null","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"NOT NULL recorded_at"},{"name":"subject_ownership_adoptions_session_actor_not_null","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"NOT NULL session_actor"},{"name":"subject_ownership_adoptions_shape","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"CHECK ((((kind = 'fresh'::text) AND (maintenance_reference IS NULL) AND (manifest_sha256 IS NULL) AND (inventory_sha256 IS NULL) AND (receipt_data IS NULL)) OR ((kind = 'legacy'::text) AND (maintenance_reference IS NOT NULL) AND (manifest_sha256 IS NOT NULL) AND (inventory_sha256 IS NOT NULL) AND (manifest_sha256 ~ '^[0-9a-f]{64}$'::text) AND (inventory_sha256 ~ '^[0-9a-f]{64}$'::text) AND (receipt_data IS NOT NULL))))"},{"name":"subject_ownership_namespaces_contract_version_check","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"CHECK ((contract_version = 1))"},{"name":"subject_ownership_namespaces_contract_version_not_null","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"NOT NULL contract_version"},{"name":"subject_ownership_namespaces_environment_id_fkey","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT"},{"name":"subject_ownership_namespaces_environment_id_not_null","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"subject_ownership_namespaces_environment_id_origin_key","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"UNIQUE (environment_id, origin)"},{"name":"subject_ownership_namespaces_issuer_host_key","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"UNIQUE (issuer_host)"},{"name":"subject_ownership_namespaces_issuer_host_not_null","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"NOT NULL issuer_host"},{"name":"subject_ownership_namespaces_origin_check","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"CHECK ((origin = ANY (ARRAY['legacy'::text, 'fresh'::text])))"},{"name":"subject_ownership_namespaces_origin_not_null","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"NOT NULL origin"},{"name":"subject_ownership_namespaces_pkey","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"PRIMARY KEY (environment_id)"},{"name":"subject_ownership_namespaces_recorded_at_not_null","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"NOT NULL recorded_at"},{"name":"user_attribute_sources_attribute_values_check","deferred":false,"relation":"user_attribute_sources","validated":true,"deferrable":false,"definition":"CHECK ((jsonb_typeof(attribute_values) = 'object'::text))"},{"name":"user_attribute_sources_attribute_values_not_null","deferred":false,"relation":"user_attribute_sources","validated":true,"deferrable":false,"definition":"NOT NULL attribute_values"},{"name":"user_attribute_sources_check","deferred":false,"relation":"user_attribute_sources","validated":true,"deferrable":false,"definition":"CHECK ((expires_at > observed_at))"},{"name":"user_attribute_sources_check1","deferred":false,"relation":"user_attribute_sources","validated":true,"deferrable":false,"definition":"CHECK ((((source_kind = 'LOCAL'::text) AND (source_namespace = 'local'::text) AND (connection_id IS NULL)) OR ((source_kind = 'EXTERNAL'::text) AND (connection_id IS NOT NULL) AND (source_namespace = ('connection:'::text || (connection_id)::text)))))"},{"name":"user_attribute_sources_end_user_id_not_null","deferred":false,"relation":"user_attribute_sources","validated":true,"deferrable":false,"definition":"NOT NULL end_user_id"},{"name":"user_attribute_sources_environment_id_connection_id_fkey","deferred":false,"relation":"user_attribute_sources","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id, connection_id) REFERENCES aegaeon.connections(environment_id, id)"},{"name":"user_attribute_sources_environment_id_end_user_id_fkey","deferred":false,"relation":"user_attribute_sources","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id, end_user_id) REFERENCES aegaeon.end_users(environment_id, id) ON DELETE CASCADE"},{"name":"user_attribute_sources_environment_id_not_null","deferred":false,"relation":"user_attribute_sources","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"user_attribute_sources_observed_at_check","deferred":false,"relation":"user_attribute_sources","validated":true,"deferrable":false,"definition":"CHECK ((observed_at >= 0))"},{"name":"user_attribute_sources_observed_at_not_null","deferred":false,"relation":"user_attribute_sources","validated":true,"deferrable":false,"definition":"NOT NULL observed_at"},{"name":"user_attribute_sources_pkey","deferred":false,"relation":"user_attribute_sources","validated":true,"deferrable":false,"definition":"PRIMARY KEY (environment_id, end_user_id, source_namespace)"},{"name":"user_attribute_sources_revision_check","deferred":false,"relation":"user_attribute_sources","validated":true,"deferrable":false,"definition":"CHECK ((revision > 0))"},{"name":"user_attribute_sources_revision_not_null","deferred":false,"relation":"user_attribute_sources","validated":true,"deferrable":false,"definition":"NOT NULL revision"},{"name":"user_attribute_sources_source_authority_check","deferred":false,"relation":"user_attribute_sources","validated":true,"deferrable":false,"definition":"CHECK (((length(source_authority) >= 1) AND (length(source_authority) <= 512)))"},{"name":"user_attribute_sources_source_authority_not_null","deferred":false,"relation":"user_attribute_sources","validated":true,"deferrable":false,"definition":"NOT NULL source_authority"},{"name":"user_attribute_sources_source_kind_check","deferred":false,"relation":"user_attribute_sources","validated":true,"deferrable":false,"definition":"CHECK ((source_kind = ANY (ARRAY['LOCAL'::text, 'EXTERNAL'::text])))"},{"name":"user_attribute_sources_source_kind_not_null","deferred":false,"relation":"user_attribute_sources","validated":true,"deferrable":false,"definition":"NOT NULL source_kind"},{"name":"user_attribute_sources_source_namespace_not_null","deferred":false,"relation":"user_attribute_sources","validated":true,"deferrable":false,"definition":"NOT NULL source_namespace"},{"name":"user_attribute_sources_source_revision_check","deferred":false,"relation":"user_attribute_sources","validated":true,"deferrable":false,"definition":"CHECK (((length(source_revision) >= 1) AND (length(source_revision) <= 512)))"},{"name":"user_attribute_sources_source_revision_not_null","deferred":false,"relation":"user_attribute_sources","validated":true,"deferrable":false,"definition":"NOT NULL source_revision"},{"name":"user_attribute_sources_updated_at_not_null","deferred":false,"relation":"user_attribute_sources","validated":true,"deferrable":false,"definition":"NOT NULL updated_at"}]}$physical$::jsonb;
  expected_functions jsonb := $functions$[{"result":"boolean","strict":true,"defaults":null,"language":"sql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_ownership_valid_subject(text)","volatility":"i","body_sha256":"fc9882541afc9a780cb6caf80c97d96fe8be21e62568205f8e7ef7be2b349eb6","security_definer":false},{"result":"trigger","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_ownership_guard_insert()","volatility":"v","body_sha256":"52b9475146e50d85310a14c71ead5c119d0b6b202f8bb521928c36c46739497f","security_definer":false},{"result":"trigger","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_ownership_immutable()","volatility":"v","body_sha256":"c365d747fb17ea03ac06aa4612a993663f3dbf74c6fb47240fcdc856d159d9d2","security_definer":false},{"result":"trigger","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_ownership_guard_environment()","volatility":"v","body_sha256":"6406ec1158669d7225bb0c5e09595ab2517e849df4cbf892c652628e46cb2d58","security_definer":true},{"result":"trigger","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_ownership_guard_user()","volatility":"v","body_sha256":"9614948221b7e5aa281211f40a79a7536c465ba5d5fa6dd091eb4fb29668c34d","security_definer":true},{"result":"bytea","strict":true,"defaults":null,"language":"sql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_frame(bytea)","volatility":"i","body_sha256":"73af3455a9d9ed6d84a6b2d177850c382d37cc03538db945d99ed4e50c6536c5","security_definer":false},{"result":"bytea","strict":true,"defaults":null,"language":"sql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_chain_start(text)","volatility":"i","body_sha256":"6a89cf6cfeaf7b67228160c980a685d2340106c53c81d5d282cc68f7a8d30444","security_definer":false},{"result":"bytea","strict":true,"defaults":null,"language":"sql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_chain_row(bytea,bigint,text,text)","volatility":"i","body_sha256":"995e91e793b4bb0b8441035c374ae62c48afd83b1fc79f4731b976377d441599","security_definer":false},{"result":"text","strict":true,"defaults":null,"language":"sql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_chain_end(bytea,bigint)","volatility":"i","body_sha256":"00c46633113a05cbd996b6bc36d9fb55874d2c964a4ca1675188756bc5067290","security_definer":false},{"result":"void","strict":false,"defaults":"0","language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_strict_json(json,integer)","volatility":"i","body_sha256":"de16f880ea0c9ff4ef15676b05d2cb42b1fd86ef1c760563de9cbf323f0b38bd","security_definer":false},{"result":"void","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_require_keys(jsonb,text[])","volatility":"i","body_sha256":"5b3e7a080c1ad342fc617a2d11632708df22395107c024a631b22775ab998324","security_definer":false},{"result":"text","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_require_string(jsonb,text)","volatility":"i","body_sha256":"d51baf6bfdfe6c472679c279e366dd8bbba63140694a9a8f7e7e8d39483d61d6","security_definer":false},{"result":"void","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_check_maintenance_role(text)","volatility":"s","body_sha256":"4edfc7e9214bc6bb316e03e2d06f4277cac9adb66f7014dea0f264385c6d58fd","security_definer":false},{"result":"text","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_maintenance_actor()","volatility":"s","body_sha256":"8d62d6f1ac5189b60e6a0553e4e361109776468f33a8de1c6064e3bfe0e981ee","security_definer":true},{"result":"void","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_check_runtime_role(text)","volatility":"s","body_sha256":"42adf6981fe4083cabc1be02f50b756b26f096d1c6b19d77480488a263939fcb","security_definer":false},{"result":"void","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_lock()","volatility":"v","body_sha256":"d90cd5e96c4381389cce2e50b40d8383dbbc10f82de8f11686745b4dd0ea9e61","security_definer":false},{"result":"regclass","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_revision_relation()","volatility":"s","body_sha256":"d64c499c2301b4ba5c0d25a375434dbd0a4d6321e8db419d8ca7773e5f5575c4","security_definer":false},{"result":"TABLE(row_key text, row_text text)","strict":false,"defaults":null,"language":"plpgsql","settings":["datestyle=iso, ymd","extra_float_digits=3","intervalstyle=postgres","search_path=pg_catalog, pg_temp","timezone=utc"],"signature":"aegaeon.subject_history_revision_rows()","volatility":"s","body_sha256":"1674cf69df8522d842fb678547ea047d64db68293a702421e42d44610a3bf73d","security_definer":false},{"result":"void","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_lock_revisions()","volatility":"v","body_sha256":"4504247c9f8d02f60f728d5a13778bc37c0f065e1949f8ee1cf24e4a1d3e28b3","security_definer":false},{"result":"TABLE(row_key text, row_text text)","strict":false,"defaults":null,"language":"sql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_physical_catalog(text)","volatility":"s","body_sha256":"1c89cd9e265783e876dbece2c49a737a3ced52ce972057d97e36559087240253","security_definer":false},{"result":"text","strict":true,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_key(text[])","volatility":"i","body_sha256":"8ae3364074e7f5b84b1f36e23fc893d5c55b64fb9db00d8ebce3fceb467dce39","security_definer":false},{"result":"TABLE(collection_name text, row_key text, row_text text)","strict":false,"defaults":null,"language":"plpgsql","settings":["datestyle=iso, ymd","extra_float_digits=3","intervalstyle=postgres","search_path=pg_catalog, pg_temp","timezone=utc"],"signature":"aegaeon.subject_history_source_rows(text)","volatility":"s","body_sha256":"a0625351b63ad3180f2b0898f847ef5b30e4653548273174c2272f452c2f2567","security_definer":false},{"result":"text","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_content_id(text,text[],text[])","volatility":"i","body_sha256":"f857b4ccabedc2c61d12ab699db33a8d7bd24cb5c46c15a57e5fe75d731c9250","security_definer":false},{"result":"jsonb","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_fact(text,text,text,uuid,uuid,text)","volatility":"i","body_sha256":"50c81e2960f390c6395fe4ff7c1eafd9e70d1a8c06703f52dc3e5d7c2963b072","security_definer":false},{"result":"jsonb","strict":false,"defaults":null,"language":"sql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_finding(text,text,text,text,uuid,jsonb,jsonb,jsonb)","volatility":"i","body_sha256":"5e48222af63e3b68f8c9889789b307ca9898ad44a34b3dd0f9521d457e24b42e","security_definer":false},{"result":"TABLE(record_type text, payload jsonb)","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_classify(text,text,text,uuid)","volatility":"s","body_sha256":"4234db1e406f61682c13c52bd27c5809d261a08fe19a92656f7d35ea6a421314","security_definer":false},{"result":"jsonb","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_document_schema(text)","volatility":"i","body_sha256":"39cd34d015032e888a7ae344126f163f624b415bed7e1aa11107af3396d6f875","security_definer":false},{"result":"void","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_validate_shape(jsonb,jsonb,jsonb)","volatility":"i","body_sha256":"1d4453458e87bed963c4d3519234082e48e4ba3a657b8a249a0e53306cb67a09","security_definer":false},{"result":"jsonb","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_parse_document(bytea,text)","volatility":"i","body_sha256":"b18bc5ce79110960ba66a2e5aca7f6c1707c82bb2c1bdbaa9cfb53c523884b16","security_definer":false},{"result":"void","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_source_refs(jsonb,jsonb,text,boolean)","volatility":"i","body_sha256":"f67403f7dbc56971dbac94e03f488a3c480a43e9c17d1be31c614b7b514f357b","security_definer":false},{"result":"void","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_validate_manifest(jsonb)","volatility":"i","body_sha256":"091c069b1d18676295e2f107c96512ed006e2f985886798bf6a62888e4dba071","security_definer":false},{"result":"jsonb","strict":false,"defaults":null,"language":"sql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_observed_physical()","volatility":"s","body_sha256":"48167055f82069035b57101be872df325f01ec6edb41b5c4177105b7df2cbf44","security_definer":false},{"result":"TABLE(record_type text, row_key text, payload text)","strict":false,"defaults":null,"language":"plpgsql","settings":["datestyle=iso, ymd","extra_float_digits=3","intervalstyle=postgres","search_path=pg_catalog, pg_temp","timezone=utc"],"signature":"aegaeon.subject_history_inventory_stream(uuid,text,text,jsonb)","volatility":"v","body_sha256":"492e346cf2a26b45ff29054d9883d6ec4e4aa276c6ea01fa2dd04ae608f1058f","security_definer":false},{"result":"TABLE(record_type text, row_key text, payload text)","strict":false,"defaults":null,"language":"plpgsql","settings":["datestyle=iso, ymd","extra_float_digits=3","intervalstyle=postgres","search_path=pg_catalog, pg_temp","timezone=utc"],"signature":"aegaeon.inventory_subject_ownership_history_v1(uuid,text,text,jsonb)","volatility":"v","body_sha256":"163a5a4186fb6931bfe5ad36b37b8b2009442665ad37700c43140e4a28aca6ed","security_definer":true},{"result":"boolean","strict":false,"defaults":null,"language":"sql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_identity_event(text)","volatility":"i","body_sha256":"6089a7cc7506b6b595b0cc0dd16e9973b8207fe3bc98d325c61e2c9dcb2cf7ef","security_definer":false},{"result":"void","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.subject_history_validate_union(jsonb,jsonb)","volatility":"i","body_sha256":"8483684ad930becb24f663ea50086cfc7c6249dc6d109ff0ac8858906d11d6f4","security_definer":false},{"result":"TABLE(environment_id uuid, receipt_id uuid, manifest_sha256 text, inventory_sha256 text, session_actor text, effective_actor text, definer_actor text, owner_count bigint, reservation_count bigint)","strict":false,"defaults":null,"language":"plpgsql","settings":["datestyle=iso, ymd","extra_float_digits=3","intervalstyle=postgres","search_path=pg_catalog, pg_temp","timezone=utc"],"signature":"aegaeon.adopt_subject_ownership_history_v1(bytea,bytea,text,text)","volatility":"v","body_sha256":"403dd259b7863e50b410efbcabf3baade2321926d6e64ae535bc20966dc642f0","security_definer":true},{"result":"TABLE(record_type text, row_key text, payload text)","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.validate_subject_ownership_namespace_v1(uuid)","volatility":"s","body_sha256":"6edd9f6fe332c899235ccf1f8be4f8af146796ceb17719386d27252b99753c06","security_definer":true},{"result":"trigger","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.organization_identity_guard()","volatility":"v","body_sha256":"aa1993954d5cb5578bf38c2e1cbeed39b06de445203b9cad675dba267deed357","security_definer":false},{"result":"trigger","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.organization_identity_credential_guard()","volatility":"v","body_sha256":"eb9397a2b4200cd51feccbc907f6d4645fddc102a5382da9a0248348e901e93d","security_definer":false},{"result":"trigger","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.organization_identity_policy_guard()","volatility":"v","body_sha256":"c2575e594679525f3e580836f591d3ff90e2de3bed94d5bdc77d0233c834e076","security_definer":false},{"result":"trigger","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.organization_identity_profile_guard()","volatility":"v","body_sha256":"95f67919a88f0d56a093c8f9e842c0a5657b890c536ce33fdadab5c0e05879c4","security_definer":false},{"result":"trigger","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.organization_support_policy_guard()","volatility":"v","body_sha256":"5b9bd0a9e4fb15a45453e53a2b17787e508fec1dd8de936f637bc85e79c7f52e","security_definer":false},{"result":"trigger","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.organization_admin_access_guard()","volatility":"v","body_sha256":"7863613f1ab6ef056feb2209e70456236344ea61dd1c55f20df18fae7f006a7d","security_definer":false},{"result":"TABLE(row_key text, row_data text)","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.organization_snapshot_history_v1(uuid,uuid,text,text,integer)","volatility":"s","body_sha256":"81965f596fecfed8787dec2f34633e6b9418901132322d45880087820840b224","security_definer":true},{"result":"TABLE(row_key text, row_data text)","strict":false,"defaults":null,"language":"plpgsql","settings":["datestyle=iso, ymd","search_path=pg_catalog, pg_temp","timezone=utc"],"signature":"aegaeon.organization_import_target_v1(uuid,text,text,jsonb)","volatility":"s","body_sha256":"60727b925406cfaab2ad459e501b072d073ce927edc5e63e08592f6356f086d8","security_definer":true},{"result":"trigger","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.organization_import_hold_guard()","volatility":"v","body_sha256":"51f613df936516301ac65c0acaf239df42c5e684abdb4ac34bd8fd26e4cdbd20","security_definer":false},{"result":"jsonb","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.organization_import_operation_v1(uuid,uuid,uuid,text)","volatility":"s","body_sha256":"90283a2439388cbba1f67bc18934fa187220f1c80ba7126922ac2a041ed69b58","security_definer":true},{"result":"void","strict":false,"defaults":null,"language":"plpgsql","settings":["datestyle=iso, ymd","search_path=pg_catalog, pg_temp","timezone=utc"],"signature":"aegaeon.organization_import_begin_v1(uuid,uuid,uuid,text,jsonb,jsonb)","volatility":"v","body_sha256":"e7a77dad39a95f395d3e7fef5cd726cdaed802b0798df59660bdaf6a1d7f1cd4","security_definer":true},{"result":"void","strict":false,"defaults":null,"language":"plpgsql","settings":["datestyle=iso, ymd","search_path=pg_catalog, pg_temp","timezone=utc"],"signature":"aegaeon.organization_import_row_v1(uuid,text,jsonb)","volatility":"v","body_sha256":"7524b6a9c8ebf210b547c295c65a38354317689f3d256c65b907588be998a12f","security_definer":true},{"result":"jsonb","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.organization_import_finish_v1(uuid)","volatility":"v","body_sha256":"ce4f2da5ca3546fb4cd67bd6ff9704667c83071da70d1550cd3bcb7ceaa3427c","security_definer":true},{"result":"bytea","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.organization_creation_record_v1(jsonb)","volatility":"v","body_sha256":"43c3c4732792a4827981a0e2c0488e53852755eb29f5cd0f49fb09fb13bd77f5","security_definer":true},{"result":"jsonb","strict":false,"defaults":null,"language":"plpgsql","settings":["search_path=pg_catalog, pg_temp"],"signature":"aegaeon.restore_subject_history_page_v1(jsonb)","volatility":"v","body_sha256":"28e816d6503dfa1740f1d4987a3cecd0760a72ac9fc1952aa4b5f335971d7aa6","security_definer":true},{"result":"TABLE(row_key text, row_data text)","strict":false,"defaults":null,"language":"plpgsql","settings":["datestyle=iso, ymd","search_path=pg_catalog, pg_temp","timezone=utc"],"signature":"aegaeon.organization_import_prepared_rows_v1(uuid,uuid,uuid,text,text,text,integer)","volatility":"s","body_sha256":"a21c847dc7ff7143637cd219a5a889065d32fdc65e099b286d8cd32fc23d1318","security_definer":true}]$functions$::jsonb;
  expected_revisions jsonb := $revisions$[{"version":"20260803140000","description":"baseline","sha256_base64":"MiEiQpBNweRvDKhVVt17w7Td1YklwRIaQ6GXfRwCmjE="},{"version":"20260909070000","description":"authorization_consents","sha256_base64":"PEdKG9v67t73TfECEz8BkuHoh0DaH7/pS57dHwGWEWY="},{"version":"20260909090000","description":"authorization_logins","sha256_base64":"z9IBFYQfQuCGGm08Ndc50Q461gDjhRzOu3YJUQ98ij8="},{"version":"20260909120000","description":"token_exchange_policy","sha256_base64":"r6cY8qHe7i1SBvcCYCy5KX2WY/YHAQr3p04fLN7SZyo="},{"version":"20260911090000","description":"application_authorizations","sha256_base64":"X4s7SL8Qx+0r+dZtKEg3rSOsFikvh0zoyFuZsAE4Vn4="},{"version":"20260913090000","description":"application_authorization_identities","sha256_base64":"EVIREfQ3EgynjVT8qwujTqVIvaNzLfAUvyPYIxUBaL0="},{"version":"20260930090000","description":"client_credentials_policy","sha256_base64":"7hvvi5YVMmIdeLRyVJ4DZodwsU41SzCBxvBBybrguVg="},{"version":"20261002100000","description":"federation_entity_cache_expiration","sha256_base64":"aXx8Kzx7ocHoDWcxzqi1ynHZBSto+yJbqGxwdVmoBos="},{"version":"20261012000000","description":"logout_confirmations","sha256_base64":"ctGR2iCLtJs22yPiEuM3APoI+NEQQvxy4r12uhXIRKs="},{"version":"20261013090000","description":"account_link_provenance","sha256_base64":"NCZ3ZERLE5/F24QzlHvCdfxaYBP+bP5qzhd+WVCV9to="},{"version":"20261027000000","description":"introspection_signing_key_slots","sha256_base64":"E135E///65/y+XDFMddJIlSOWftAJBIF4AZ/XprmngU="},{"version":"20261027010000","description":"public_client_jwk_storage","sha256_base64":"OY5UQArSHoP1eUg6mK+Se2uERmsbMRinsbGCWPLPwwk="},{"version":"20261027020000","description":"registration_metadata_consistency","sha256_base64":"ljnWpvT6uF7Ma6PITeb94FrjpgNA7+xqP/RCezsn4Mw="},{"version":"20261029010000","description":"access_token_rs256_signing","sha256_base64":"B4Rp6c4DUMTlSyoTVsYjybD8EgMZUazW3X+MD1QctzQ="},{"version":"20261029020000","description":"client_secret_active_slots","sha256_base64":"q06T/+jfGNYyyS1ikRwcnw9pQwg0HAKYyKNCMm33CAE="},{"version":"20261029030000","description":"client_dpop_minimum","sha256_base64":"blCGVrSaC6qVw7X6doPmPWEkEzCuxZAmXcOLWVP2w6M="},{"version":"20261029050000","description":"subject_ownership","sha256_base64":"L9IEz/x70ZuAEdiEtNC1QHDpbyYgamJZIFGGmmbrGSw="},{"version":"20261029051000","description":"subject_audit_authority","sha256_base64":"RCKSAUsEcLRdyv2M7iutqGBZyrD3S4SOydz381o+ehg="},{"version":"20261029052000","description":"subject_prerequisite_catalog","sha256_base64":"Xo6EWnSpFG4Wpa1AbE5KwvplQXWNq1Snj1mDMXLVYPk="},{"version":"20261101090000","description":"user_attribute_sources","sha256_base64":"bYD2g9+6L9RLpq9R/s3Eli1685Pj0k6MFLGGaPs2LFI="},{"version":"20261102100000","description":"lti_platform","sha256_base64":"QutQwF4eo3CSIXn6Rxi17OZJDMYZ4t+/05GzLcZ0z6c="},{"version":"20261102101000","description":"lti_subject_inventory","sha256_base64":"Vmf2k2WGVN/6Y7vfhsym4Vee+smPwD8PYaKRFRY8YlE="},{"version":"20261102102000","description":"lti_admission_index","sha256_base64":"oMGfhGMR4cKnQBHsTvRIUM1kPONI5Fr2+cjOwrJVyio="},{"version":"20261102103000","description":"lti_admission_inventory","sha256_base64":"5nadHdz9PJb1iAoqYMwYl1GtXbTPFnlJP4rSlukBbtg="},{"version":"20261105000000","description":"organizations","sha256_base64":null}]$revisions$::jsonb;
  actual jsonb; item jsonb; observed record; identity regprocedure; seen text[]:=ARRAY[]::text[]; revision_id text; digest_value text;
BEGIN
  IF pg_catalog.current_setting('server_encoding')<>'UTF8' OR pg_catalog.current_setting('server_version_num')::integer/10000<>18 THEN RAISE EXCEPTION 'unsupported subject history PostgreSQL supplier'; END IF;
  PERFORM aegaeon.subject_history_check_runtime_role(runtime_name);
  IF (SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname IN ('aegaeon_subject_owner','aegaeon_subject_maintenance')
      AND NOT (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))<>2
    OR EXISTS(SELECT FROM pg_catalog.pg_auth_members WHERE member IN ('aegaeon_subject_owner'::regrole,'aegaeon_subject_maintenance'::regrole))
    OR pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE')
    OR pg_catalog.has_schema_privilege('aegaeon_subject_maintenance','aegaeon','CREATE') THEN RAISE EXCEPTION 'subject authority role shape is incompatible'; END IF;
  -- Validate every explicitly enrolled maintenance member, not just this caller.
  -- pg_has_role(superuser,...) is deliberately not a membership enumeration.
  FOR observed IN WITH RECURSIVE administrators(oid) AS (
      SELECT o.member
      FROM pg_catalog.pg_auth_members o
      JOIN pg_catalog.pg_auth_members m ON m.member=o.member AND m.grantor=o.grantor
      JOIN pg_catalog.pg_roles grantor ON grantor.oid=o.grantor AND grantor.rolsuper
      WHERE o.roleid='aegaeon_subject_owner'::regrole
        AND m.roleid='aegaeon_subject_maintenance'::regrole
        AND o.admin_option AND NOT o.inherit_option AND NOT o.set_option
        AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
    ), members(oid) AS (
      SELECT 'aegaeon_subject_maintenance'::regrole::oid
      UNION SELECT a.member FROM pg_catalog.pg_auth_members a JOIN members m ON a.roleid=m.oid
        WHERE NOT EXISTS (SELECT FROM administrators d WHERE d.oid=a.member)
    ) SELECT r.rolname FROM members m JOIN pg_catalog.pg_roles r ON r.oid=m.oid LOOP
    PERFORM aegaeon.subject_history_check_maintenance_role(observed.rolname);
  END LOOP;
  actual := aegaeon.subject_history_observed_physical();
  IF actual IS DISTINCT FROM expected THEN RAISE EXCEPTION 'subject physical schema or trigger definition mismatch'; END IF;
  IF EXISTS(SELECT FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='aegaeon' AND c.relname IN ('environments','end_users','end_user_password_credentials','end_user_profiles','user_attribute_sources','lti_registrations','lti_registration_revisions','lti_identifiers','lti_launch_intents','subject_ownership_namespaces','subject_ownership_adoptions','end_user_identity_owners','end_user_subject_reservations','authorization_domains','authorization_domain_targets','application_organizations','organization_role_definitions','organization_memberships','organization_authority_events','organization_authority_outbox','organization_authority_receipts','organization_operator_grants','organization_client_bindings','organization_invitations','organization_invitation_challenges','organization_identity_requests','organization_admin_access_grants','organization_import_operations','organization_creation_receipts','subject_history_restorations','subject_history_restoration_pages')
      AND (c.relkind<>'r' OR c.relpersistence<>'p' OR c.relrowsecurity OR c.relforcerowsecurity
        OR (c.relname NOT IN ('environments','end_users','end_user_password_credentials','end_user_profiles','user_attribute_sources','lti_registrations','lti_registration_revisions','lti_identifiers','lti_launch_intents') AND c.relowner<>'aegaeon_subject_owner'::regrole))) THEN RAISE EXCEPTION 'subject relation authority mismatch'; END IF;
  -- The complete audit corpus is an input, including every attached partition.
  -- Never let owner/bypass differences turn an inventory into a filtered view.
  IF EXISTS(SELECT FROM pg_catalog.pg_partition_tree('aegaeon.audit_events'::regclass) t
      JOIN pg_catalog.pg_class c ON c.oid=t.relid
      WHERE c.relrowsecurity OR c.relforcerowsecurity) THEN
    RAISE EXCEPTION 'subject audit corpus row security is unsupported';
  END IF;
  IF EXISTS(SELECT FROM pg_catalog.pg_constraint con
      JOIN pg_catalog.pg_class c ON c.oid=con.conrelid
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      LEFT JOIN pg_catalog.pg_index i ON i.indexrelid=con.conindid
      WHERE n.nspname='aegaeon' AND c.relname IN ('environments','end_users','end_user_password_credentials','end_user_profiles','user_attribute_sources','lti_registrations','lti_registration_revisions','lti_identifiers','lti_launch_intents','subject_ownership_namespaces','subject_ownership_adoptions','end_user_identity_owners','end_user_subject_reservations','authorization_domains','authorization_domain_targets','application_organizations','organization_role_definitions','organization_memberships','organization_authority_events','organization_authority_outbox','organization_authority_receipts','organization_operator_grants','organization_client_bindings','organization_invitations','organization_invitation_challenges','organization_identity_requests','organization_admin_access_grants','organization_import_operations','organization_creation_receipts','subject_history_restorations','subject_history_restoration_pages')
        AND con.contype IN ('p','u') AND (i.indexrelid IS NULL OR NOT i.indisunique
          OR NOT i.indisvalid OR NOT i.indisready OR NOT i.indislive OR NOT i.indimmediate
          OR i.indpred IS NOT NULL OR i.indexprs IS NOT NULL)) THEN
    RAISE EXCEPTION 'subject ownership key index is not a valid immediate unique authority';
  END IF;
  FOR item IN SELECT pg_catalog.jsonb_array_elements(expected->'triggers') LOOP
    IF NOT EXISTS(SELECT FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='aegaeon' AND c.relname=item->>'relation' AND t.tgname=item->>'name'
        AND t.tgfoid=pg_catalog.to_regprocedure('aegaeon.'||(item->>'function')||'()') AND t.tgconstraint=0) THEN RAISE EXCEPTION 'subject trigger function binding mismatch'; END IF;
  END LOOP;
  FOR item IN SELECT pg_catalog.jsonb_array_elements(expected_functions) LOOP
    identity := pg_catalog.to_regprocedure(item->>'signature');
    IF identity IS NULL THEN RAISE EXCEPTION 'subject protected function is missing'; END IF;
    SELECT p.*,l.lanname INTO observed FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang WHERE p.oid=identity;
    IF observed.proowner<>'aegaeon_subject_owner'::regrole
       OR observed.prosecdef IS DISTINCT FROM (item->>'security_definer')::boolean
       OR observed.provolatile::text<>item->>'volatility' OR observed.lanname<>item->>'language'
       OR observed.proisstrict IS DISTINCT FROM (item->>'strict')::boolean
       OR pg_catalog.pg_get_function_result(identity) IS DISTINCT FROM item->>'result'
       OR pg_catalog.pg_get_expr(observed.proargdefaults,0) IS DISTINCT FROM item->>'defaults'
       OR pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(observed.prosrc,'UTF8')),'hex')<>item->>'body_sha256'
       OR (SELECT pg_catalog.jsonb_agg(pg_catalog.lower(v) ORDER BY pg_catalog.lower(v) COLLATE "C") FROM pg_catalog.unnest(observed.proconfig) settings(v)) IS DISTINCT FROM item->'settings'
    THEN RAISE EXCEPTION 'subject protected function definition mismatch'; END IF;
  END LOOP;
  IF EXISTS (SELECT FROM pg_catalog.pg_proc p
    CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
    WHERE p.oid='aegaeon.organization_snapshot_history_v1(uuid,uuid,text,text,integer)'::regprocedure
      AND (a.grantee NOT IN ('aegaeon_subject_owner'::regrole,runtime_name::regrole)
        OR a.privilege_type<>'EXECUTE' OR (a.grantee<>'aegaeon_subject_owner'::regrole AND a.is_grantable))) THEN
    RAISE EXCEPTION 'snapshot history entry has unrelated or grantable authority';
  END IF;
  IF NOT pg_catalog.has_function_privilege('aegaeon_subject_maintenance','aegaeon.organization_import_target_v1(uuid,text,text,jsonb)','EXECUTE') OR EXISTS (SELECT FROM pg_catalog.pg_proc p
    CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
    WHERE p.oid='aegaeon.organization_import_target_v1(uuid,text,text,jsonb)'::regprocedure
      AND (a.grantee NOT IN ('aegaeon_subject_owner'::regrole,'aegaeon_subject_maintenance'::regrole)
        OR a.privilege_type<>'EXECUTE' OR (a.grantee<>'aegaeon_subject_owner'::regrole AND a.is_grantable))) THEN
    RAISE EXCEPTION 'import target entry is not execute-only maintenance authority';
  END IF;
  FOR identity IN SELECT unnest(ARRAY[
    'aegaeon.restore_subject_history_page_v1(jsonb)'::regprocedure,
    'aegaeon.organization_import_prepared_rows_v1(uuid,uuid,uuid,text,text,text,integer)'::regprocedure,
    'aegaeon.organization_import_operation_v1(uuid,uuid,uuid,text)'::regprocedure,
    'aegaeon.organization_import_begin_v1(uuid,uuid,uuid,text,jsonb,jsonb)'::regprocedure,
    'aegaeon.organization_import_row_v1(uuid,text,jsonb)'::regprocedure,
    'aegaeon.organization_import_finish_v1(uuid)'::regprocedure]) LOOP
    IF NOT pg_catalog.has_function_privilege('aegaeon_subject_maintenance',identity,'EXECUTE') OR EXISTS(
      SELECT FROM pg_catalog.pg_proc p CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
      WHERE p.oid=identity AND (a.grantee NOT IN ('aegaeon_subject_owner'::regrole,'aegaeon_subject_maintenance'::regrole)
        OR a.privilege_type<>'EXECUTE' OR (a.grantee<>'aegaeon_subject_owner'::regrole AND a.is_grantable))) THEN
      RAISE EXCEPTION 'inactive import entry is not execute-only maintenance authority';
    END IF;
  END LOOP;
  IF pg_catalog.has_table_privilege(runtime_name,'aegaeon.organization_import_operations','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
    OR pg_catalog.has_any_column_privilege(runtime_name,'aegaeon.organization_import_operations','SELECT,INSERT,UPDATE,REFERENCES') THEN
    RAISE EXCEPTION 'runtime has direct inactive import authority';
  END IF;
  IF EXISTS (SELECT FROM pg_catalog.pg_proc p
    CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
    WHERE p.oid='aegaeon.organization_creation_record_v1(jsonb)'::regprocedure
      AND (a.grantee NOT IN ('aegaeon_subject_owner'::regrole,runtime_name::regrole)
        OR a.privilege_type<>'EXECUTE' OR (a.grantee<>'aegaeon_subject_owner'::regrole AND a.is_grantable))) THEN
    RAISE EXCEPTION 'creation receipt entry has unrelated or grantable authority';
  END IF;
  FOR observed IN SELECT * FROM aegaeon.subject_history_revision_rows() LOOP
    actual := observed.row_text::jsonb; revision_id := actual->>'version';
    SELECT value INTO item FROM pg_catalog.jsonb_array_elements(expected_revisions) fields(value)
      WHERE revision_id=value->>'version' OR revision_id=(value->>'version')||'_'||(value->>'description');
    IF item IS NULL OR (item->>'version')=ANY(seen) THEN RAISE EXCEPTION 'unexpected or duplicate Atlas revision'; END IF;
    seen := pg_catalog.array_append(seen,item->>'version');
    IF actual->>'description' IS DISTINCT FROM item->>'description'
      OR (actual->>'applied') IS NULL OR (actual->>'total') IS NULL OR (actual->>'total')::bigint<=0
      OR (actual->>'applied')::bigint<>(actual->>'total')::bigint OR COALESCE(actual->>'error','')<>'' THEN RAISE EXCEPTION 'incomplete Atlas revision state'; END IF;
    digest_value := pg_catalog.regexp_replace(actual->>'hash','^h1:','');
    IF digest_value IS NULL OR digest_value !~ '^[A-Za-z0-9+/]{43}=$' THEN RAISE EXCEPTION 'invalid Atlas revision hash'; END IF;
    IF item->>'sha256_base64' IS NOT NULL AND digest_value<>item->>'sha256_base64'
      AND digest_value IS DISTINCT FROM item->>'published_prefix_hash' THEN RAISE EXCEPTION 'predecessor Atlas revision hash mismatch'; END IF;
  END LOOP;
  IF pg_catalog.cardinality(seen)<>pg_catalog.jsonb_array_length(expected_revisions) THEN RAISE EXCEPTION 'missing Atlas revision'; END IF;
  -- This version identifies the expected physical contract, not this file's hash.
  RETURN pg_catalog.encode(pg_catalog.sha256(aegaeon.subject_history_frame(pg_catalog.convert_to('aegaeon-subject-physical-v1','UTF8'))
    ||aegaeon.subject_history_frame(pg_catalog.convert_to(expected::text,'UTF8'))
    ||aegaeon.subject_history_frame(pg_catalog.convert_to(expected_functions::text,'UTF8'))
    ||aegaeon.subject_history_frame(pg_catalog.convert_to(expected_revisions::text,'UTF8'))),'hex');
END
$function$;
$definition$;
RESET ROLE;
END
$catalog$;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;

-- END ORGANIZATIONS COMPONENT catalog

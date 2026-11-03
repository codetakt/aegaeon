-- Optional LTI capability attached to an existing canonical client identity.
-- This migration does not adopt historical subject ownership or activate LTI.
CREATE TABLE aegaeon.lti_registrations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id uuid NOT NULL REFERENCES aegaeon.environments(id) ON DELETE RESTRICT,
    client_record_id uuid NOT NULL REFERENCES aegaeon.clients(id) ON DELETE RESTRICT,
    client_id text NOT NULL,
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    active_revision bigint,
    UNIQUE (environment_id, client_id),
    UNIQUE (environment_id, id),
    CHECK (active_revision IS NULL OR (active_revision > 0 AND active_revision <= revision))
);

CREATE TABLE aegaeon.lti_registration_revisions (
    registration_id uuid NOT NULL REFERENCES aegaeon.lti_registrations(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object' AND octet_length(document::text) <= 1048576),
    author_id uuid NOT NULL REFERENCES aegaeon.administrators(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (registration_id, revision)
);

ALTER TABLE aegaeon.lti_registrations ADD CONSTRAINT lti_active_revision_fkey
FOREIGN KEY (id, active_revision) REFERENCES aegaeon.lti_registration_revisions(registration_id, revision)
DEFERRABLE INITIALLY DEFERRED;

-- Reserve placement identities even if an object is disabled or retired.
CREATE TABLE aegaeon.lti_identifiers (
    environment_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('deployment', 'resource_link')),
    identifier text COLLATE "C" NOT NULL CHECK (octet_length(identifier) BETWEEN 1 AND 255),
    registration_id uuid NOT NULL,
    deployment_id text COLLATE "C" NOT NULL,
    context_id text COLLATE "C",
    PRIMARY KEY (environment_id, kind, identifier),
    FOREIGN KEY (environment_id, registration_id) REFERENCES aegaeon.lti_registrations(environment_id,id) ON DELETE RESTRICT
);

CREATE TABLE aegaeon.lti_launch_intents (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id uuid NOT NULL,
    registration_id uuid NOT NULL,
    revision bigint NOT NULL,
    runtime_revision uuid NOT NULL,
    runtime_fingerprint text NOT NULL,
    owner_id uuid NOT NULL,
    subject text COLLATE "C" NOT NULL,
    producer_client_id text NOT NULL,
    producer_token_digest text NOT NULL,
    producer_metadata jsonb NOT NULL,
    deployment_id text COLLATE "C" NOT NULL,
    resource_link_id text COLLATE "C" NOT NULL,
    roles jsonb NOT NULL CHECK (jsonb_typeof(roles) = 'array'),
    ticket_hash text NOT NULL UNIQUE,
    login_hint_hash text UNIQUE,
    message_hint_hash text UNIQUE,
    session_hash text,
    csrf_hash text,
    continuation_hash text UNIQUE,
    authorization_request jsonb,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','confirmed','initiated','consumed','cancelled')),
    created_at bigint NOT NULL,
    expires_at bigint NOT NULL,
    consumed_at bigint,
    response_digest text,
    CHECK (expires_at > created_at AND expires_at <= created_at + 300),
    FOREIGN KEY (environment_id, registration_id) REFERENCES aegaeon.lti_registrations(environment_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (registration_id, revision) REFERENCES aegaeon.lti_registration_revisions(registration_id,revision) ON DELETE RESTRICT,
    CHECK (octet_length(producer_metadata::text) <= 65536),
    CHECK (authorization_request IS NULL OR octet_length(authorization_request::text) <= 65536)
);
CREATE INDEX lti_launch_intents_expiry_idx ON aegaeon.lti_launch_intents(expires_at);

CREATE FUNCTION aegaeon.lti_immutable_record() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $body$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'LTI identities and revisions are immutable';
END
$body$;
CREATE TRIGGER lti_revision_immutable BEFORE UPDATE OR DELETE ON aegaeon.lti_registration_revisions
FOR EACH ROW EXECUTE FUNCTION aegaeon.lti_immutable_record();
CREATE TRIGGER lti_identifier_immutable BEFORE UPDATE OR DELETE ON aegaeon.lti_identifiers
FOR EACH ROW EXECUTE FUNCTION aegaeon.lti_immutable_record();
CREATE TRIGGER lti_revision_no_truncate BEFORE TRUNCATE ON aegaeon.lti_registration_revisions
FOR EACH STATEMENT EXECUTE FUNCTION aegaeon.lti_immutable_record();
CREATE TRIGGER lti_identifier_no_truncate BEFORE TRUNCATE ON aegaeon.lti_identifiers
FOR EACH STATEMENT EXECUTE FUNCTION aegaeon.lti_immutable_record();

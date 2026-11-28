-- Apply once as the schema owner in the dedicated BFF database. Supply
-- serving_role using psql -v serving_role=... . No issuer tables are used.
\set ON_ERROR_STOP on
BEGIN;
CREATE SCHEMA hosted_invitation;
REVOKE ALL ON SCHEMA hosted_invitation FROM PUBLIC;
CREATE TABLE hosted_invitation.flow (
    id uuid PRIMARY KEY,
    environment uuid NOT NULL,
    browser_tag text NOT NULL,
    domain_id uuid NOT NULL,
    invitation uuid NOT NULL,
    handle uuid NOT NULL UNIQUE,
    oauth_tag text UNIQUE,
    deadline bigint NOT NULL,
    sealed bytea NOT NULL CHECK (octet_length(sealed) <= 65536),
    UNIQUE(environment,browser_tag,domain_id,invitation)
);
CREATE INDEX flow_expiry ON hosted_invitation.flow(environment,deadline);
CREATE TABLE hosted_invitation.cleanup (
    id uuid PRIMARY KEY,
    environment uuid NOT NULL,
    deadline bigint NOT NULL,
    retry_at bigint NOT NULL DEFAULT 0,
    sealed bytea NOT NULL
);
CREATE INDEX cleanup_due ON hosted_invitation.cleanup(environment,retry_at);
REVOKE ALL ON ALL TABLES IN SCHEMA hosted_invitation FROM PUBLIC;
GRANT USAGE ON SCHEMA hosted_invitation TO :"serving_role";
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA hosted_invitation TO :"serving_role";
COMMIT;

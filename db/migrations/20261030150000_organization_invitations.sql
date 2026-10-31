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

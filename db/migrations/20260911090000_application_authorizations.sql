-- Privileged application projections are independent of editable OIDC profiles.
-- Keep tombstones and monotonic revisions so removal/recreation cannot revive grants.
CREATE TABLE aegaeon.application_authorizations (
    environment_id uuid NOT NULL REFERENCES aegaeon.environments(id) ON DELETE CASCADE,
    client_id text NOT NULL CHECK (length(client_id) BETWEEN 1 AND 255),
    subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
    revision bigint NOT NULL CHECK (revision > 0),
    authority text NOT NULL CHECK (length(authority) BETWEEN 1 AND 255),
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    audiences jsonb NOT NULL CHECK (jsonb_typeof(audiences) = 'array'),
    claims jsonb NOT NULL CHECK (jsonb_typeof(claims) = 'object'),
    enabled boolean NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (environment_id, client_id, subject)
);

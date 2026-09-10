-- Per-request authorization consent; the form's raw synchronizer token is never stored.
CREATE TABLE aegaeon.authorization_consents (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id uuid NOT NULL REFERENCES aegaeon.environments(id) ON DELETE CASCADE,
    issuer text NOT NULL,
    subject text NOT NULL,
    session_sha256 text NOT NULL,
    token_sha256 text NOT NULL UNIQUE,
    authorize_uri text NOT NULL,
    request_snapshot jsonb NOT NULL CHECK (jsonb_typeof(request_snapshot) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    decision text CHECK (decision IN ('approve', 'deny')),
    decided_at timestamptz,
    CHECK ((decision IS NULL) = (decided_at IS NULL))
);
CREATE INDEX authorization_consents_environment_idx
    ON aegaeon.authorization_consents(environment_id, expires_at);

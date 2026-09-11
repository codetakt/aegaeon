-- Request-bound local authentication; raw challenge, browser and session tokens
-- are not stored. Completion and consumption are separate one-way transitions.
CREATE TABLE aegaeon.authorization_logins (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id uuid NOT NULL REFERENCES aegaeon.environments(id) ON DELETE CASCADE,
    issuer text NOT NULL,
    client_id text NOT NULL,
    token_sha256 text NOT NULL UNIQUE,
    browser_sha256 text NOT NULL,
    authorize_uri text NOT NULL,
    request_snapshot jsonb NOT NULL CHECK (jsonb_typeof(request_snapshot) = 'object'),
    csrf_sha256 text,
    session_snapshot jsonb CHECK (jsonb_typeof(session_snapshot) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    completed_at timestamptz,
    consumed_at timestamptz,
    CHECK ((session_snapshot IS NULL) = (completed_at IS NULL)),
    CHECK (consumed_at IS NULL OR completed_at IS NOT NULL)
);
CREATE INDEX authorization_logins_environment_idx
    ON aegaeon.authorization_logins(environment_id, expires_at);

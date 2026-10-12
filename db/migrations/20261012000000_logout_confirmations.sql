-- Short-lived browser-bound RP logout decisions. Retain decided rows until expiry
-- so completing a request cannot refund its transaction admission budget.
CREATE TABLE aegaeon.logout_confirmations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id uuid NOT NULL REFERENCES aegaeon.environments(id) ON DELETE CASCADE,
    issuer text NOT NULL,
    token_sha256 text NOT NULL UNIQUE,
    browser_sha256 text NOT NULL,
    request_snapshot jsonb NOT NULL CHECK (jsonb_typeof(request_snapshot) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    presented_at timestamptz,
    session_sha256 text,
    subject text,
    decision text CHECK (decision IN ('confirm', 'cancel')),
    decided_at timestamptz,
    CHECK ((session_sha256 IS NULL) = (subject IS NULL)),
    CHECK (presented_at IS NOT NULL OR session_sha256 IS NULL),
    CHECK ((decision IS NULL) = (decided_at IS NULL)),
    CHECK (decision IS NULL OR presented_at IS NOT NULL)
);
CREATE INDEX logout_confirmations_environment_idx
    ON aegaeon.logout_confirmations(environment_id, expires_at);

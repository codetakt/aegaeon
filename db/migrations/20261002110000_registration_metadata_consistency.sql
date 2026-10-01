-- Atlas executes this file transactionally. Stop all writers before applying.
-- Lock parent rows/tables before DCR, preserving the administration lock order.
LOCK TABLE aegaeon.environments, aegaeon.clients, aegaeon.dynamic_client_registrations IN SHARE ROW EXCLUSIVE MODE;
DO $migration$
DECLARE unresolved boolean;
BEGIN
    SELECT issues.blocked INTO unresolved FROM (
WITH registrations AS (
    SELECT c.environment_id, c.id AS client_id, c.client_identifier,
           c.configuration_version_id, c.status::text AS status,
           c.redirect_uris, c.allowed_grant_types,
           c.token_endpoint_authentication_method AS auth_method,
           d.response_types, d.jwks, d.jwks_uri
    FROM aegaeon.dynamic_client_registrations d
    JOIN aegaeon.clients c ON c.environment_id = d.environment_id AND c.id = d.client_id
), findings AS (
    SELECT r.*, issue.reason, issue.blocks_upgrade
    FROM registrations r
    CROSS JOIN LATERAL (VALUES
        ('code_requires_redirect', true,
            'authorization_code' = ANY(r.allowed_grant_types) AND cardinality(r.redirect_uris) = 0),
        ('refresh_requires_code', true,
            'refresh_token' = ANY(r.allowed_grant_types) AND NOT 'authorization_code' = ANY(r.allowed_grant_types)),
        ('authenticated_grant_requires_authentication', true,
            r.auth_method = 'none' AND r.allowed_grant_types && ARRAY['client_credentials', 'urn:ietf:params:oauth:grant-type:token-exchange']),
        ('redirect_contains_ascii_whitespace_or_control', true,
            EXISTS (SELECT 1 FROM unnest(r.redirect_uris) u WHERE u COLLATE "C" ~ '[[:space:][:cntrl:]]')),
        ('malformed_inline_key_envelope', true,
            r.jwks IS NOT NULL AND CASE
                WHEN jsonb_typeof(r.jwks) <> 'object' OR jsonb_typeof(r.jwks->'keys') IS DISTINCT FROM 'array' THEN true
                ELSE NOT EXISTS (
                    SELECT 1 FROM jsonb_array_elements(r.jwks->'keys') k
                    WHERE lower(COALESCE(k->>'use', 'sig')) <> 'enc'
                      AND (k->'key_ops' IS NULL OR k->'key_ops' = 'null'::jsonb OR
                           CASE WHEN jsonb_typeof(k->'key_ops') = 'array' THEN EXISTS (
                               SELECT 1 FROM jsonb_array_elements_text(k->'key_ops') op WHERE lower(op) IN ('sign', 'verify')
                           ) ELSE false END)
                ) OR EXISTS (
                    SELECT 1 FROM jsonb_array_elements(r.jwks->'keys') k
                    WHERE jsonb_typeof(k) <> 'object'
                       OR k->>'kty' IS NULL OR k->>'kty' NOT IN ('RSA', 'EC')
                       OR EXISTS (SELECT 1 FROM unnest(ARRAY['kid','alg','use']) f
                                  WHERE k->f IS NOT NULL AND jsonb_typeof(k->f) NOT IN ('string','null'))
                       OR CASE WHEN k->>'kty' = 'RSA' THEN
                            jsonb_typeof(k->'n') IS DISTINCT FROM 'string' OR jsonb_typeof(k->'e') IS DISTINCT FROM 'string'
                          WHEN k->>'kty' = 'EC' THEN
                            jsonb_typeof(k->'crv') IS DISTINCT FROM 'string' OR jsonb_typeof(k->'x') IS DISTINCT FROM 'string' OR jsonb_typeof(k->'y') IS DISTINCT FROM 'string'
                          ELSE false END
                       OR CASE WHEN k->'key_ops' IS NULL OR k->'key_ops' = 'null'::jsonb THEN false
                               WHEN jsonb_typeof(k->'key_ops') <> 'array' THEN true
                               ELSE EXISTS (SELECT 1 FROM jsonb_array_elements(k->'key_ops') op WHERE jsonb_typeof(op) <> 'string') END
                ) OR EXISTS (
                    SELECT 1 FROM jsonb_array_elements(r.jwks->'keys') k
                    WHERE jsonb_typeof(k->'kid') = 'string' GROUP BY k->>'kid' HAVING count(*) > 1
                ) END),
        ('malformed_remote_key_uri_envelope', true,
            r.jwks_uri IS NOT NULL AND r.jwks_uri !~* '^https://[^/?#@[:space:][:cntrl:]]+([/?][^#[:space:][:cntrl:]]*)?$'),
        ('private_key_jwt_requires_key_source', true,
            r.auth_method = 'private_key_jwt' AND r.jwks IS NULL AND r.jwks_uri IS NULL),
        ('derive_response_types', false,
            r.response_types <> CASE WHEN 'authorization_code' = ANY(r.allowed_grant_types) THEN ARRAY['code'] ELSE ARRAY[]::text[] END),
        ('clear_unused_remote_key_source', false, r.jwks IS NOT NULL AND r.jwks_uri IS NOT NULL)
    ) AS issue(reason, blocks_upgrade, present)
    WHERE issue.present
)
SELECT EXISTS (SELECT 1 FROM findings WHERE blocks_upgrade) AS blocked
    ) issues;
    IF unresolved THEN
        RAISE EXCEPTION 'registration metadata upgrade blocked; run scripts/operations/dcr-metadata-preflight.sql and repair every blocking finding';
    END IF;
END
$migration$;

ALTER TABLE aegaeon.dynamic_client_registrations
    DROP CONSTRAINT dynamic_client_registrations_response_types_shape;
UPDATE aegaeon.dynamic_client_registrations d
SET response_types = CASE WHEN 'authorization_code' = ANY(c.allowed_grant_types)
                          THEN ARRAY['code'] ELSE ARRAY[]::text[] END
FROM aegaeon.clients c
WHERE c.environment_id = d.environment_id AND c.id = d.client_id
  AND d.response_types IS DISTINCT FROM CASE WHEN 'authorization_code' = ANY(c.allowed_grant_types)
                          THEN ARRAY['code'] ELSE ARRAY[]::text[] END;
-- Inline-first runtime selection is unchanged. The metadata fingerprint does change.
UPDATE aegaeon.dynamic_client_registrations
SET jwks_uri = NULL
WHERE jwks IS NOT NULL AND jwks_uri IS NOT NULL;
ALTER TABLE aegaeon.dynamic_client_registrations
    ADD CONSTRAINT dynamic_client_registrations_responses_v2 CHECK (response_types = ARRAY[]::text[] OR response_types = ARRAY['code']),
    ADD CONSTRAINT dynamic_client_registrations_key_source_v1 CHECK (jwks IS NULL OR jwks_uri IS NULL);

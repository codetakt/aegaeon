-- Reference projection retained as a pgcrypto oracle for hash compatibility tests.

WITH active_runtime_client_projection AS (
  SELECT
    rt.environment_id AS environment_id,
    rt.configuration_version_id AS configuration_version_id,
    c.created_at AS client_created_at,
    c.id AS client_id,
    c.client_identifier,
    c.redirect_uris,
    c.allowed_grant_types,
    c.allowed_scopes,
    c.token_endpoint_authentication_method,
    COALESCE(dcr.post_logout_redirect_uris, ARRAY[]::text[]) AS post_logout_redirect_uris,
    dcr.backchannel_logout_uri,
    COALESCE(dcr.backchannel_logout_session_required, false) AS backchannel_logout_session_required,
    dcr.jwks_uri,
    dcr.jwks,
    dcr.token_endpoint_auth_signing_alg,
    EXTRACT(EPOCH FROM dcr.client_id_issued_at)::BIGINT AS client_id_issued_at_epoch_secs,
    COALESCE(secret_projection.client_secret_hashes, ARRAY[]::text[]) AS client_secret_hashes,
    COALESCE(
      secret_projection.client_secret_expires_at_epoch_secs,
      ARRAY[]::bigint[]
    ) AS client_secret_expires_at_epoch_secs,
    jsonb_build_object(
      'environment_id', rt.environment_id::text,
      'configuration_version_id', rt.configuration_version_id::text,
      'client_id', c.id::text,
      'client_identifier', c.client_identifier,
      'redirect_uris', to_jsonb(c.redirect_uris),
      'allowed_grant_types', to_jsonb(c.allowed_grant_types),
      'allowed_scopes', to_jsonb(c.allowed_scopes),
      'token_endpoint_authentication_method', c.token_endpoint_authentication_method,
      'post_logout_redirect_uris', to_jsonb(COALESCE(dcr.post_logout_redirect_uris, ARRAY[]::text[])),
      'backchannel_logout_uri', dcr.backchannel_logout_uri,
      'backchannel_logout_session_required', COALESCE(dcr.backchannel_logout_session_required, false),
      'jwks_uri', dcr.jwks_uri,
      'jwks', dcr.jwks,
      'token_endpoint_auth_signing_alg', dcr.token_endpoint_auth_signing_alg,
      'client_id_issued_at_epoch_secs', EXTRACT(EPOCH FROM dcr.client_id_issued_at)::BIGINT,
      'client_secret_credentials', COALESCE(secret_projection.client_secret_credentials, '[]'::jsonb)
    ) AS row_json
  FROM aegaeon.clients c
  JOIN aegaeon.active_runtime_environments rt
    ON rt.environment_id = c.environment_id
  LEFT JOIN aegaeon.dynamic_client_registrations dcr
    ON dcr.environment_id = c.environment_id
   AND dcr.client_id = c.id
  LEFT JOIN LATERAL (
    SELECT
      array_agg(cs.secret_hash ORDER BY cs.created_at, cs.id) AS client_secret_hashes,
      array_agg(
        EXTRACT(EPOCH FROM cs.expires_at)::BIGINT
        ORDER BY cs.created_at, cs.id
      ) AS client_secret_expires_at_epoch_secs,
      jsonb_agg(
        jsonb_build_object(
          'secret_hash', cs.secret_hash,
          'expires_at_epoch_secs', EXTRACT(EPOCH FROM cs.expires_at)::BIGINT
        )
        ORDER BY cs.created_at, cs.id
      ) AS client_secret_credentials
    FROM aegaeon.client_secrets cs
    WHERE cs.environment_id = c.environment_id
      AND cs.client_id = c.id
      AND cs.status = 'ACTIVE'
      AND cs.expires_at > now()
      AND cs.secret_hash_algorithm = 'argon2id'
  ) secret_projection ON TRUE
  WHERE rt.issuer_host = $1
    AND c.status = 'ACTIVE'
    AND c.configuration_version_id = rt.configuration_version_id
)
SELECT encode(
  aegaeon.digest(
    COALESCE(
      jsonb_agg(row_json ORDER BY environment_id, client_created_at, client_id)::text,
      '[]'
    ),
    'sha256'
  ),
  'hex'
) AS active_runtime_client_fingerprint
FROM active_runtime_client_projection

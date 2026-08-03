pub(crate) const ACTIVE_RUNTIME_AUTHORITY_REVISION_FOR_ISSUER_HOST: &str = r"
SELECT
  rt.configuration_version_id AS active_configuration_version_id,
  encode(digest(rt.configuration_document::text, 'sha256'), 'hex')
    AS active_configuration_document_fingerprint,
  encode(
    digest(
      COALESCE((
        SELECT jsonb_agg(projected.row_json ORDER BY projected.usage, projected.status, projected.kid, projected.id)::text
        FROM (
          SELECT
            rk.id,
            rk.usage::text AS usage,
            rk.status::text AS status,
            rk.kid,
            jsonb_build_object(
              'id', rk.id::text,
              'configuration_version_id', rk.configuration_version_id::text,
              'usage', rk.usage::text,
              'kid', rk.kid,
              'algorithm', rk.algorithm,
              'provider', rk.provider::text,
              'status', rk.status::text,
              'retiring_expires_at', rk.retiring_expires_at,
              'public_jwk', rk.public_jwk,
              'key_handle_sha256', encode(digest(rk.key_handle, 'sha256'), 'hex'),
              'provider_configuration', rk.provider_configuration
            ) AS row_json
          FROM aegaeon.runtime_keys rk
          WHERE rk.environment_id = rt.environment_id
            AND (
              rk.status = 'ACTIVE'
              OR (rk.status = 'RETIRING' AND rk.retiring_expires_at > now())
            )
        ) projected
      ), '[]'),
      'sha256'
    ),
    'hex'
  ) AS active_runtime_key_set_fingerprint,
  encode(
    digest(
      COALESCE((
        SELECT jsonb_build_object(
          'token_hash', bearer.token_hash,
          'token_hash_algorithm', bearer.token_hash_algorithm
        )::text
        FROM aegaeon.environment_dcr_bearer_tokens bearer
        WHERE bearer.environment_id = rt.environment_id
          AND bearer.token_hash_algorithm = 'sha256'
      ), 'null'),
      'sha256'
    ),
    'hex'
  ) AS active_dcr_bearer_token_fingerprint
FROM aegaeon.active_runtime_environments rt
WHERE rt.issuer_host = $1
ORDER BY rt.environment_id
LIMIT 2
";

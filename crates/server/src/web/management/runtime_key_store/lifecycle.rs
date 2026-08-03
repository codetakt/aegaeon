use super::super::management_internal_error;
use super::super::runtime_keys::RuntimeKeyUsageInput;
use crate::management::types::PolicyDocument;
use axum::response::Response;
use sqlx::{postgres::PgRow, Postgres, Transaction};
use uuid::Uuid;

pub(in crate::web::management) async fn retire_active_runtime_keys(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    usage: RuntimeKeyUsageInput,
    retiring_retention_seconds: i64,
    request_id: &str,
) -> Result<(), Response> {
    sqlx::query(
        r"
UPDATE aegaeon.runtime_keys
SET
  status = 'RETIRING',
  retiring_expires_at = now() + (GREATEST($3::bigint, 1) * interval '1 second')
WHERE environment_id = $1
  AND usage = $2::aegaeon.runtime_key_usage
  AND status = 'ACTIVE'
        ",
    )
    .bind(environment_id)
    .bind(usage.as_db_str())
    .bind(retiring_retention_seconds)
    .execute(&mut **tx)
    .await
    .map(|_| ())
    .map_err(|_| management_internal_error(request_id, "Failed to retire active runtime keys"))
}

pub(in crate::web::management) fn runtime_key_retiring_retention_seconds(
    policy: &PolicyDocument,
    usage: RuntimeKeyUsageInput,
) -> i64 {
    let primary_ttl = match usage {
        RuntimeKeyUsageInput::OidcIdTokenSigning => policy.id_token_time_to_live_seconds,
        RuntimeKeyUsageInput::OidcRequestObjectDecryption => policy
            .request_object_jti_ttl_seconds
            .max(policy.authorization_code_time_to_live_seconds),
        RuntimeKeyUsageInput::JwtAccessTokenSigning => policy.access_token_time_to_live_seconds,
        RuntimeKeyUsageInput::JwtIntrospectionSigning => policy.jwt_introspection_exp_seconds,
    };

    i64::from(primary_ttl)
        .saturating_add(i64::from(policy.jwt_leeway_seconds))
        .max(1)
}

pub(in crate::web::management) async fn activate_next_runtime_key_row(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    usage: RuntimeKeyUsageInput,
    request_id: &str,
) -> Result<Option<PgRow>, Response> {
    sqlx::query(
        r#"
UPDATE aegaeon.runtime_keys
SET status = 'ACTIVE', activated_at = now(), retiring_expires_at = NULL
WHERE environment_id = $1
  AND usage = $2::aegaeon.runtime_key_usage
  AND status = 'NEXT'
RETURNING
  id,
  environment_id,
  usage::text AS usage,
  kid,
  algorithm,
  provider::text AS provider,
  status::text AS status,
  public_jwk,
  provider_configuration,
  to_char(retiring_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS retiring_expires_at,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
        "#,
    )
    .bind(environment_id)
    .bind(usage.as_db_str())
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to activate runtime key"))
}

pub(in crate::web::management) async fn load_next_runtime_key_row_for_update(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    usage: RuntimeKeyUsageInput,
    request_id: &str,
) -> Result<Option<PgRow>, Response> {
    sqlx::query(
        r#"
SELECT
  rk.id,
  rk.environment_id,
  rk.usage::text AS usage,
  rk.kid,
  rk.algorithm,
  rk.provider::text AS provider,
  rk.status::text AS status,
  rk.public_jwk,
  rk.provider_configuration,
  to_char(rk.retiring_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS retiring_expires_at,
  to_char(rk.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
FROM aegaeon.runtime_keys rk
WHERE rk.environment_id = $1
  AND rk.usage = $2::aegaeon.runtime_key_usage
  AND rk.status = 'NEXT'
FOR UPDATE OF rk
        "#,
    )
    .bind(environment_id)
    .bind(usage.as_db_str())
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to load next runtime key"))
}

pub(in crate::web::management) async fn revoke_runtime_key_row(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    environment_id: Uuid,
    runtime_key_id: Uuid,
    request_id: &str,
) -> Result<Option<PgRow>, Response> {
    sqlx::query(
        r#"
UPDATE aegaeon.runtime_keys rk
SET status = 'REVOKED', revoked_at = now(), retiring_expires_at = NULL
FROM aegaeon.environments e
JOIN aegaeon.tenants t ON t.id = e.tenant_id
WHERE rk.id = $1
  AND rk.environment_id = $2
  AND rk.environment_id = e.id
  AND rk.status <> 'REVOKED'
  AND t.team_id = $3
RETURNING
  rk.id,
  rk.environment_id,
  rk.usage::text AS usage,
  rk.kid,
  rk.algorithm,
  rk.provider::text AS provider,
  rk.status::text AS status,
  rk.public_jwk,
  rk.provider_configuration,
  to_char(rk.retiring_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS retiring_expires_at,
  to_char(rk.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
        "#,
    )
    .bind(runtime_key_id)
    .bind(environment_id)
    .bind(team_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to revoke runtime key"))
}

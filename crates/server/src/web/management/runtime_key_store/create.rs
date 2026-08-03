use super::super::runtime_keys::{runtime_key_bad_request, RuntimeKeyCreateInput};
use super::super::ManagementEnvironmentRecord;
use axum::response::Response;
use sqlx::{postgres::PgRow, Postgres, Transaction};

pub(in crate::web::management) async fn insert_runtime_key_row(
    tx: &mut Transaction<'_, Postgres>,
    environment: &ManagementEnvironmentRecord,
    input: &RuntimeKeyCreateInput,
    request_id: &str,
) -> Result<PgRow, Response> {
    sqlx::query(
        r#"
INSERT INTO aegaeon.runtime_keys (
  environment_id, configuration_version_id, usage, kid, algorithm, provider, status,
  public_jwk, key_handle, provider_configuration, activated_at
)
VALUES (
  $1,
  $2,
  $3::aegaeon.runtime_key_usage,
  $4,
  $5,
  $6::aegaeon.runtime_key_provider,
  $7::aegaeon.runtime_key_status,
  $8,
  $9,
  $10,
  CASE WHEN $7 = 'ACTIVE' THEN now() ELSE NULL END
)
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
    .bind(environment.scope.environment)
    .bind(environment.active_configuration_version_id)
    .bind(input.usage.as_db_str())
    .bind(&input.kid)
    .bind(&input.algorithm)
    .bind(&input.provider)
    .bind(input.initial_status)
    .bind(&input.public_jwk)
    .bind(&input.encrypted_key_handle)
    .bind(&input.provider_configuration)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| {
        runtime_key_bad_request(
            request_id,
            "Failed to create runtime key (unique constraint?)",
            None,
        )
    })
}

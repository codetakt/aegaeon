use super::{
    RuntimeKey, RuntimeKeyAlgorithm, RuntimeKeyProvider, RuntimeKeySet, RuntimeKeySetError,
    RuntimeKeyStatus, RuntimeKeyUsage,
};
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

const ACTIVE_RUNTIME_KEYS_FOR_ISSUER_HOST: &str = r"
SELECT
  rk.environment_id,
  rk.usage::text AS usage,
  rk.algorithm,
  rk.provider::text AS provider,
  rk.status::text AS status,
  EXTRACT(EPOCH FROM rk.retiring_expires_at)::BIGINT AS retiring_expires_at_epoch_secs,
  rk.kid,
  rk.public_jwk,
  rk.key_handle,
  rk.provider_configuration
FROM aegaeon.active_runtime_environments rt
JOIN aegaeon.runtime_keys rk
  ON rk.environment_id = rt.environment_id
WHERE rt.issuer_host = $1
  AND (
    rk.status = 'ACTIVE'
    OR (rk.status = 'RETIRING' AND rk.retiring_expires_at > now())
  )
ORDER BY rk.usage, rk.status, rk.created_at, rk.id
";

const ACTIVE_RUNTIME_KEYS_FOR_ENVIRONMENT: &str = r"
SELECT
  rk.environment_id,
  rk.usage::text AS usage,
  rk.algorithm,
  rk.provider::text AS provider,
  rk.status::text AS status,
  EXTRACT(EPOCH FROM rk.retiring_expires_at)::BIGINT AS retiring_expires_at_epoch_secs,
  rk.kid,
  rk.public_jwk,
  rk.key_handle,
  rk.provider_configuration
FROM aegaeon.runtime_keys rk
WHERE rk.environment_id = $1
  AND (
    rk.status = 'ACTIVE'
    OR (rk.status = 'RETIRING' AND rk.retiring_expires_at > now())
  )
ORDER BY rk.usage, rk.status, rk.created_at, rk.id
";

pub async fn load_runtime_key_set_for_issuer_host_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    issuer_host: &str,
) -> Result<RuntimeKeySet, RuntimeKeySetError> {
    let rows = sqlx::query(ACTIVE_RUNTIME_KEYS_FOR_ISSUER_HOST)
        .bind(issuer_host)
        .fetch_all(&mut **tx)
        .await
        .map_err(RuntimeKeySetError::DatabaseQuery)?;

    runtime_key_set_from_rows(&rows)
}

pub async fn load_runtime_key_set_for_environment_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
) -> Result<RuntimeKeySet, RuntimeKeySetError> {
    let rows = sqlx::query(ACTIVE_RUNTIME_KEYS_FOR_ENVIRONMENT)
        .bind(environment_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(RuntimeKeySetError::DatabaseQuery)?;

    runtime_key_set_from_rows(&rows)
}

fn runtime_key_set_from_rows(
    rows: &[sqlx::postgres::PgRow],
) -> Result<RuntimeKeySet, RuntimeKeySetError> {
    rows.iter()
        .map(runtime_key_from_row)
        .collect::<Result<Vec<_>, _>>()
        .and_then(RuntimeKeySet::try_new)
}

fn runtime_key_from_row(row: &sqlx::postgres::PgRow) -> Result<RuntimeKey, RuntimeKeySetError> {
    let environment_id = row
        .try_get::<Uuid, _>("environment_id")
        .map_err(|_| RuntimeKeySetError::RowDecode("environment_id"))?;
    let usage = RuntimeKeyUsage::try_from_db(
        &row.try_get::<String, _>("usage")
            .map_err(|_| RuntimeKeySetError::RowDecode("usage"))?,
    )?;
    let algorithm = RuntimeKeyAlgorithm::try_from_db(
        &row.try_get::<String, _>("algorithm")
            .map_err(|_| RuntimeKeySetError::RowDecode("algorithm"))?,
    )?;
    let provider = RuntimeKeyProvider::try_from_db(
        &row.try_get::<String, _>("provider")
            .map_err(|_| RuntimeKeySetError::RowDecode("provider"))?,
    )?;
    let status = RuntimeKeyStatus::try_from_db(
        &row.try_get::<String, _>("status")
            .map_err(|_| RuntimeKeySetError::RowDecode("status"))?,
    )?;
    let retiring_expires_at_epoch_secs = row
        .try_get::<Option<i64>, _>("retiring_expires_at_epoch_secs")
        .map_err(|_| RuntimeKeySetError::RowDecode("retiring_expires_at_epoch_secs"))?;
    let kid = row
        .try_get::<String, _>("kid")
        .map_err(|_| RuntimeKeySetError::RowDecode("kid"))?;
    let public_jwk = serde_json::from_value(
        row.try_get::<Value, _>("public_jwk")
            .map_err(|_| RuntimeKeySetError::RowDecode("public_jwk"))?,
    )
    .map_err(RuntimeKeySetError::InvalidPublicJwk)?;
    let key_handle = row
        .try_get::<String, _>("key_handle")
        .map_err(|_| RuntimeKeySetError::RowDecode("key_handle"))?;
    let provider_configuration = row
        .try_get::<Value, _>("provider_configuration")
        .map_err(|_| RuntimeKeySetError::RowDecode("provider_configuration"))?;

    Ok(RuntimeKey {
        environment_id,
        usage,
        algorithm,
        provider,
        status,
        retiring_expires_at_epoch_secs,
        kid,
        public_jwk,
        key_handle,
        provider_configuration,
    })
}

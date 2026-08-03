use super::super::super::configuration_documents::EnvironmentConfigurationState;
use super::super::super::management_internal_error;
use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(super) async fn upsert_environment_key_store_state(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    state: &EnvironmentConfigurationState,
    request_id: &str,
) -> Result<(), Response> {
    let key_store_configuration =
        serde_json::to_string(&state.key_store_configuration).map_err(|_| {
            management_internal_error(request_id, "Failed to serialize key store configuration")
        })?;
    sqlx::query(
        r"
INSERT INTO aegaeon.environment_key_stores (
  environment_id,
  configuration_version_id,
  type,
  configuration_public,
  redacted
)
VALUES ($1, $2, $3, $4::jsonb, $5)
ON CONFLICT (environment_id) DO UPDATE
SET
  configuration_version_id = EXCLUDED.configuration_version_id,
  type = EXCLUDED.type,
  configuration_public = EXCLUDED.configuration_public,
  redacted = EXCLUDED.redacted,
  updated_at = now()
        ",
    )
    .bind(environment_id)
    .bind(configuration_version_id)
    .bind(&state.key_store_type)
    .bind(&key_store_configuration)
    .bind(state.key_store_redacted)
    .execute(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to update environment key store"))?;

    Ok(())
}

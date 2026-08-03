use super::super::super::super::{management_internal_error, required_row_value};
use super::super::super::InitialEnvironmentConfiguration;
use axum::response::Response;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

pub(in crate::web::management::topology_support::environment_creation) async fn insert_initial_configuration_version(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    administrator_id: Uuid,
    configuration: &InitialEnvironmentConfiguration,
    request_id: &str,
) -> Result<Uuid, Response> {
    let row = sqlx::query(
        r"
INSERT INTO aegaeon.configuration_versions (
  environment_id,
  version_number,
  schema_version,
  configuration_hash,
  status,
  configuration_document,
  created_by_administrator_id,
  comment,
  activated_at
)
VALUES ($1, 1, 1, $2, 'ACTIVE', $3::jsonb, $4, $5, now())
RETURNING id
        ",
    )
    .bind(environment_id)
    .bind(&configuration.prepared_document.hash)
    .bind(&configuration.prepared_document.document)
    .bind(administrator_id)
    .bind("Initial configuration")
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to create configuration version"))?;

    row.try_get("id")
        .map_err(|_| management_internal_error(request_id, "Failed to read configuration version"))
}

pub(in crate::web::management::topology_support::environment_creation) async fn activate_environment_configuration(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    request_id: &str,
) -> Result<String, Response> {
    let row = sqlx::query(
        r#"
UPDATE aegaeon.environments
SET active_configuration_version_id = $1, updated_at = now()
WHERE id = $2
RETURNING to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
        "#,
    )
    .bind(configuration_version_id)
    .bind(environment_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to update environment"))?;

    required_row_value(
        &row,
        "updated_at",
        request_id,
        "Failed to read updated environment",
    )
}

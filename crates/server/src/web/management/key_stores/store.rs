use axum::response::Response;
use sqlx::{postgres::PgRow, PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::management::types::KeyStorePublicView;

use super::super::{management_internal_error, ManagementEnvironmentRecord};
use super::validation::ValidatedKeyStoreUpdate;

pub(in crate::web::management) const LOAD_KEY_STORE_ROW_SQL: &str = r"
SELECT ks.type, ks.configuration_public, ks.redacted
FROM aegaeon.environment_key_stores ks
JOIN aegaeon.environments e ON e.id = ks.environment_id
JOIN aegaeon.tenants t ON t.id = e.tenant_id
WHERE ks.environment_id = $1
  AND t.team_id = $2
  AND t.status <> 'DELETED'
  AND e.status <> 'DELETED'
        ";

pub(in crate::web::management::key_stores) fn key_store_public_view_from_row_result(
    row: &PgRow,
    request_id: &str,
) -> Result<KeyStorePublicView, Response> {
    Ok(KeyStorePublicView {
        type_: row
            .try_get("type")
            .map_err(|_| management_internal_error(request_id, "Failed to read key store type"))?,
        configuration: row.try_get("configuration_public").map_err(|_| {
            management_internal_error(request_id, "Failed to read key store configuration")
        })?,
        redacted: row
            .try_get("redacted")
            .map_err(|_| management_internal_error(request_id, "Failed to read key store state"))?,
    })
}

pub(in crate::web::management::key_stores) async fn load_key_store_row(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    request_id: &str,
) -> Result<Option<PgRow>, Response> {
    sqlx::query(LOAD_KEY_STORE_ROW_SQL)
        .bind(environment_id)
        .bind(team_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| management_internal_error(request_id, "Database query failed"))
}

pub(in crate::web::management::key_stores) async fn load_key_store_row_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    environment_id: Uuid,
    request_id: &str,
) -> Result<Option<PgRow>, Response> {
    sqlx::query(LOAD_KEY_STORE_ROW_SQL)
        .bind(environment_id)
        .bind(team_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| management_internal_error(request_id, "Database query failed"))
}

pub(in crate::web::management::key_stores) async fn upsert_key_store(
    tx: &mut Transaction<'_, Postgres>,
    environment: &ManagementEnvironmentRecord,
    req: &ValidatedKeyStoreUpdate,
    request_id: &str,
) -> Result<(), Response> {
    sqlx::query(
        r"
INSERT INTO aegaeon.environment_key_stores (
  environment_id, configuration_version_id, type,
  configuration_public, redacted, updated_at
)
VALUES ($1, $2, $3, $4, true, now())
ON CONFLICT (environment_id) DO UPDATE SET
  configuration_version_id = EXCLUDED.configuration_version_id,
  type = EXCLUDED.type,
  configuration_public = EXCLUDED.configuration_public,
  redacted = true,
  updated_at = now()
        ",
    )
    .bind(environment.scope.environment)
    .bind(environment.active_configuration_version_id)
    .bind(&req.type_)
    .bind(&req.configuration)
    .execute(&mut **tx)
    .await
    .map(|_| ())
    .map_err(|_| management_internal_error(request_id, "Failed to update key store"))
}

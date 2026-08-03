use super::super::super::management_internal_error;
use axum::response::Response;
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};
use uuid::Uuid;

pub(super) async fn update_environment_row(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    environment_id: Uuid,
    name: &str,
    request_id: &str,
) -> Result<Option<PgRow>, Response> {
    sqlx::query(
        r#"
UPDATE aegaeon.environments e
SET name = $1, updated_at = now()
FROM aegaeon.tenants t
WHERE e.id = $2
  AND e.tenant_id = t.id
  AND t.team_id = $3
  AND e.status <> 'DELETED'
RETURNING
  e.id,
  e.tenant_id,
  e.name,
  e.slug,
  e.issuer_host,
  e.issuer_url,
  e.active_configuration_version_id,
  to_char(e.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(e.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
        "#,
    )
    .bind(name)
    .bind(environment_id)
    .bind(team_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Database query failed"))
}

pub(super) async fn delete_environment_row(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    environment_id: Uuid,
    request_id: &str,
) -> Result<Option<String>, Response> {
    sqlx::query(
        r"
UPDATE aegaeon.environments e
SET status = 'DELETED', deleted_at = now(), updated_at = now()
FROM aegaeon.tenants t
WHERE e.id = $1
  AND e.tenant_id = t.id
  AND t.team_id = $2
  AND e.status <> 'DELETED'
RETURNING e.issuer_host
        ",
    )
    .bind(environment_id)
    .bind(team_id)
    .fetch_optional(&mut **tx)
    .await
    .and_then(|row| row.map(|row| row.try_get("issuer_host")).transpose())
    .map_err(|_| management_internal_error(request_id, "Database query failed"))
}

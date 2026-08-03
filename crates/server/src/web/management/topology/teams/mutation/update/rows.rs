use super::super::super::super::super::management_internal_error;
use axum::response::Response;
use sqlx::{postgres::PgRow, Postgres, Transaction};
use uuid::Uuid;

pub(super) async fn update_team_row(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    name: &str,
    request_id: &str,
) -> Result<Option<PgRow>, Response> {
    sqlx::query(
        r#"
UPDATE aegaeon.teams
SET name = $1, updated_at = now()
WHERE id = $2
  AND status <> 'DELETED'
RETURNING
  id,
  name,
  slug,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
        "#,
    )
    .bind(name)
    .bind(team_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Database query failed"))
}

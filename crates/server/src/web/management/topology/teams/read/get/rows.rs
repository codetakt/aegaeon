use crate::web::management::management_internal_error;
use axum::response::Response;
use sqlx::{postgres::PgRow, PgPool};
use uuid::Uuid;

pub(super) async fn get_team_row(
    pool: &PgPool,
    team_id: Uuid,
    administrator_id: Uuid,
    request_id: &str,
) -> Result<Option<PgRow>, Response> {
    sqlx::query(
        r#"
SELECT
  t.id,
  t.name,
  t.slug,
  to_char(t.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(t.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
FROM aegaeon.teams t
JOIN aegaeon.team_memberships m
  ON m.team_id = t.id
WHERE t.id = $1
  AND m.administrator_id = $2
  AND t.status <> 'DELETED'
        "#,
    )
    .bind(team_id)
    .bind(administrator_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| management_internal_error(request_id, "Database query failed"))
}

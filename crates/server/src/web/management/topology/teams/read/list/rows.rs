use crate::web::management::http_errors::management_database_error as database_error;
use crate::web::management::request_support::owned::reads;
use axum::response::Response;
use sqlx::{postgres::PgRow, PgPool};
use uuid::Uuid;

pub(super) async fn list_team_rows(
    pool: &PgPool,
    administrator_id: Uuid,
    cursor_created_at: Option<&str>,
    cursor_id: Option<&str>,
    limit_plus_one: i64,
    request_id: &str,
) -> Result<Vec<PgRow>, Response> {
    reads::all(
        pool,
        sqlx::query(
            r#"
SELECT
  t.id,
  t.name,
  t.slug,
  to_char(t.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at_cursor,
  t.id::text AS id_cursor,
  to_char(t.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(t.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
FROM aegaeon.teams t
JOIN aegaeon.team_memberships m
  ON m.team_id = t.id
WHERE m.administrator_id = $1
  AND t.status <> 'DELETED'
  AND ($2::timestamptz IS NULL OR (t.created_at, t.id) > ($2::timestamptz, $3::uuid))
ORDER BY t.created_at ASC, t.id ASC
LIMIT $4
        "#,
        )
        .bind(administrator_id)
        .bind(cursor_created_at)
        .bind(cursor_id)
        .bind(limit_plus_one),
        request_id,
    )
    .await?
    .map_err(|error| database_error(request_id, &error, "Database query failed"))
}

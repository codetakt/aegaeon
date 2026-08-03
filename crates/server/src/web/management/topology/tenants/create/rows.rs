use crate::web::management::error_response;
use axum::{http::StatusCode, response::Response};
use sqlx::{postgres::PgRow, Postgres, Transaction};
use uuid::Uuid;

use crate::web::management::topology_support::CreateTenantInput;

pub(super) async fn lock_active_team_for_tenant_creation(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    request_id: &str,
) -> Result<bool, Response> {
    sqlx::query(
        r"
SELECT t.id
FROM aegaeon.teams t
WHERE t.id = $1
  AND t.status = 'ACTIVE'
FOR UPDATE OF t
        ",
    )
    .bind(team_id)
    .fetch_optional(&mut **tx)
    .await
    .map(|row| row.is_some())
    .map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Database query failed",
            None,
            Some(request_id),
        )
    })
}

pub(super) async fn insert_tenant_row(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    input: &CreateTenantInput,
    request_id: &str,
) -> Result<PgRow, Response> {
    sqlx::query(
        r#"
INSERT INTO aegaeon.tenants (team_id, slug, name, region)
VALUES ($1, $2, $3, $4)
RETURNING
  id,
  slug,
  name,
  region,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
        "#,
    )
    .bind(team_id)
    .bind(&input.slug)
    .bind(&input.name)
    .bind(&input.region)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Failed to create tenant",
            None,
            Some(request_id),
        )
    })
}

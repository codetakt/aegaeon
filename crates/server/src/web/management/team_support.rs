use super::{error_response, row_mappers::team_with_id_from_row_result};
use crate::management::types::Team;
use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(super) async fn insert_team_owner_membership(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    administrator_id: Uuid,
    request_id: &str,
) -> Result<(), Response> {
    sqlx::query(
        r"
INSERT INTO aegaeon.team_memberships (team_id, administrator_id, role)
VALUES ($1, $2, 'OWNER')
        ",
    )
    .bind(team_id)
    .bind(administrator_id)
    .execute(&mut **tx)
    .await
    .map(|_| ())
    .map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Failed to add team membership",
            None,
            Some(request_id),
        )
    })
}

pub(super) async fn insert_team_record(
    tx: &mut Transaction<'_, Postgres>,
    name: &str,
    slug: Option<&str>,
    request_id: &str,
) -> Result<(Uuid, Team), Response> {
    let Ok(row) = sqlx::query(
        r#"
INSERT INTO aegaeon.teams (name, slug)
VALUES ($1, $2)
RETURNING
  id,
  name,
  slug,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
        "#,
    )
    .bind(name)
    .bind(slug)
    .fetch_one(&mut **tx)
    .await
    else {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Failed to create team",
            None,
            Some(request_id),
        ));
    };

    team_with_id_from_row_result(&row, request_id)
}

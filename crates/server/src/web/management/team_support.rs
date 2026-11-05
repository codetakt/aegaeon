use super::{error_response, row_mappers::team_with_id_from_row_result};
use crate::management::types::Team;
use crate::web::management::http_errors::management_database_error as database_error;
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
    .map_err(|error| database_error(request_id, &error, "Failed to add team membership"))
}

pub(super) async fn insert_team_record(
    tx: &mut Transaction<'_, Postgres>,
    name: &str,
    slug: Option<&str>,
    request_id: &str,
) -> Result<(Uuid, Team), Response> {
    let row = sqlx::query(
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
    .map_err(|error| {
        if error
            .as_database_error()
            .is_some_and(|error| error.is_unique_violation() || error.is_check_violation())
        {
            error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Failed to create team",
                None,
                Some(request_id),
            )
        } else {
            database_error(request_id, &error, "Failed to create team")
        }
    })?;

    team_with_id_from_row_result(&row, request_id)
}

use crate::web::management::http_errors::management_database_error as database_error;
use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::web::management::error_response;

pub(in crate::web::management::core::bootstrap) async fn insert_bootstrap_team(
    tx: &mut Transaction<'_, Postgres>,
    request_id: &str,
) -> Result<Uuid, Response> {
    let row = sqlx::query(
        r"
INSERT INTO aegaeon.teams (name)
VALUES ($1)
RETURNING id
        ",
    )
    .bind("Primary Team")
    .fetch_one(&mut **tx)
    .await
    .map_err(|error| database_error(request_id, &error, "Failed to create team"))?;

    row.try_get("id").map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Failed to read created team",
            None,
            Some(request_id),
        )
    })
}

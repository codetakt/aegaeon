use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::web::management::error_response;

pub(in crate::web::management::core::bootstrap) async fn insert_bootstrap_team(
    tx: &mut Transaction<'_, Postgres>,
    request_id: &str,
) -> Result<Uuid, Response> {
    let Ok(row) = sqlx::query(
        r"
INSERT INTO aegaeon.teams (name)
VALUES ($1)
RETURNING id
        ",
    )
    .bind("Primary Team")
    .fetch_one(&mut **tx)
    .await
    else {
        return Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Failed to create team",
            None,
            Some(request_id),
        ));
    };

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

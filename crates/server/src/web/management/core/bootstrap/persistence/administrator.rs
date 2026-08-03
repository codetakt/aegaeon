use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::web::management::error_response;

pub(in crate::web::management::core::bootstrap) async fn insert_bootstrap_administrator(
    tx: &mut Transaction<'_, Postgres>,
    email: &str,
    password_hash: &str,
    request_id: &str,
) -> Result<Uuid, Response> {
    let Ok(row) = sqlx::query(
        r"
INSERT INTO aegaeon.administrators (email, password_hash)
VALUES ($1, $2)
RETURNING id
        ",
    )
    .bind(email)
    .bind(password_hash)
    .fetch_one(&mut **tx)
    .await
    else {
        return Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Failed to create administrator",
            None,
            Some(request_id),
        ));
    };

    row.try_get("id").map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Failed to read created administrator",
            None,
            Some(request_id),
        )
    })
}

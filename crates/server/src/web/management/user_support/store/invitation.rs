use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::end_user_profiles;
use crate::management::types::User;

use super::super::super::{error_response, management_internal_error};
use super::super::errors::is_unique_violation;
use super::super::mapper::user_from_row_result;

pub(in crate::web::management) async fn insert_invited_user(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    subject: &str,
    email: Option<&str>,
    duplicate_message: &str,
    request_id: &str,
) -> Result<(Uuid, User), Response> {
    let row = sqlx::query(
        r#"
INSERT INTO aegaeon.end_users (
  environment_id,
  subject,
  email,
  status
)
VALUES ($1, $2, $3, 'INVITED')
RETURNING
  id,
  environment_id,
  subject,
  email,
  status::text AS status,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
        "#,
    )
    .bind(environment_id)
    .bind(subject)
    .bind(email)
    .fetch_one(&mut **tx)
    .await
    .map_err(|err| {
        if is_unique_violation(&err) {
            error_response(
                StatusCode::CONFLICT,
                "conflict",
                duplicate_message,
                None,
                Some(request_id),
            )
        } else {
            management_internal_error(request_id, "Database query failed")
        }
    })?;

    let user_id = row.get::<Uuid, _>("id");
    end_user_profiles::ensure_profile_row(tx, user_id)
        .await
        .map_err(|_| management_internal_error(request_id, "Failed to initialize user profile"))?;
    let user = user_from_row_result(&row, request_id)?;

    Ok((user_id, user))
}

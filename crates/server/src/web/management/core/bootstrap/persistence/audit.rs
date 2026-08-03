use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::audit_safety::redacted_audit_data;
use crate::web::management::error_response;

pub(in crate::web::management::core::bootstrap) async fn insert_bootstrap_audit_record(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    administrator_id: Uuid,
    email: &str,
    request_id: &str,
) -> Result<(), Response> {
    let data = serde_json::json!({
        "administratorId": administrator_id.to_string(),
        "email": email,
        "teamId": team_id.to_string(),
    });
    sqlx::query(
        r"
INSERT INTO aegaeon.audit_events (
  team_id,
  event_type,
  category,
  outcome,
  severity,
  occurred_at,
  actor_type,
  actor_id,
  target_type,
  target_id,
  request_id,
  data
)
VALUES ($1, $2, $3, $4, $5, now(), $6, $7, $8, $9, $10, $11)
        ",
    )
    .bind(team_id)
    .bind("BOOTSTRAP_OWNER")
    .bind("SYSTEM")
    .bind("SUCCESS")
    .bind("INFO")
    .bind("ADMINISTRATOR")
    .bind(administrator_id.to_string())
    .bind("TEAM")
    .bind(team_id.to_string())
    .bind(request_id)
    .bind(redacted_audit_data(data))
    .execute(&mut **tx)
    .await
    .map(|_| ())
    .map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Failed to record bootstrap audit event",
            None,
            Some(request_id),
        )
    })
}

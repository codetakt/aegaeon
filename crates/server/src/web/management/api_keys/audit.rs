use super::super::error_response;
use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::audit_safety::redacted_audit_data;

pub(super) struct ApiKeyAuditEvent {
    pub(super) event_type: &'static str,
    pub(super) severity: &'static str,
    pub(super) api_key_id: Uuid,
    pub(super) data: serde_json::Value,
}

pub(super) async fn write_api_key_audit_event(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    administrator_id: Uuid,
    request_id: &str,
    event: ApiKeyAuditEvent,
) -> Result<(), Response> {
    sqlx::query(
        r"
INSERT INTO aegaeon.audit_events (
  team_id, event_type, category, outcome, severity,
  occurred_at, actor_type, actor_id, target_type, target_id, request_id, data
)
VALUES ($1, $2, $3, $4, $5, now(), $6, $7, $8, $9, $10, $11)
        ",
    )
    .bind(team_id)
    .bind(event.event_type)
    .bind("KEY_MANAGEMENT")
    .bind("SUCCESS")
    .bind(event.severity)
    .bind("ADMINISTRATOR")
    .bind(administrator_id.to_string())
    .bind("API_KEY")
    .bind(event.api_key_id.to_string())
    .bind(request_id)
    .bind(redacted_audit_data(event.data))
    .execute(&mut **tx)
    .await
    .map(|_| ())
    .map_err(|_| {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "Audit write failed",
            None,
            Some(request_id),
        )
    })
}

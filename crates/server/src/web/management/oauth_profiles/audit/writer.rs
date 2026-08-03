use super::super::super::management_internal_error;
use super::context::OAuthProfileAuditContext;
use axum::response::Response;
use sqlx::{Postgres, Transaction};

use crate::audit_safety::redacted_audit_data;

pub(super) async fn write_oauth_profile_audit_event(
    tx: &mut Transaction<'_, Postgres>,
    audit_context: OAuthProfileAuditContext<'_>,
    event_type: &str,
    target_id: String,
    data: serde_json::Value,
) -> Result<(), Response> {
    sqlx::query(
        r"
INSERT INTO aegaeon.audit_events (
  team_id,
  tenant_id,
  environment_id,
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
VALUES ($1, $2, $3, $4, $5, $6, $7, now(), $8, $9, $10, $11, $12, $13)
        ",
    )
    .bind(audit_context.environment.scope.team)
    .bind(audit_context.environment.scope.tenant)
    .bind(audit_context.environment.scope.environment)
    .bind(event_type)
    .bind("CONTROL_PLANE")
    .bind("SUCCESS")
    .bind("INFO")
    .bind("ADMINISTRATOR")
    .bind(audit_context.administrator_id.to_string())
    .bind("OAUTH_PROFILE")
    .bind(target_id)
    .bind(audit_context.request_id)
    .bind(redacted_audit_data(data))
    .execute(&mut **tx)
    .await
    .map(|_| ())
    .map_err(|_| management_internal_error(audit_context.request_id, "Failed to write audit event"))
}

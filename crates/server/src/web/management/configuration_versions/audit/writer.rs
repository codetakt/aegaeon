use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Transaction};

use super::super::super::configuration_documents::ConfigurationVersionAuditContext;
use super::super::super::error_response;
use crate::audit_safety::redacted_audit_data;

pub(in crate::web::management::configuration_versions::audit) async fn write_configuration_version_transition_audit_event(
    tx: &mut Transaction<'_, Postgres>,
    context: &ConfigurationVersionAuditContext<'_>,
    event_type: &str,
    severity: &str,
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
  from_configuration_version_id,
  to_configuration_version_id,
  data
)
VALUES ($1, $2, $3, $4, $5, $6, $7, now(), $8, $9, $10, $11, $12, $13, $14, $15)
        ",
    )
    .bind(context.scope.team)
    .bind(context.scope.tenant)
    .bind(context.scope.environment)
    .bind(event_type)
    .bind("CONTROL_PLANE")
    .bind("SUCCESS")
    .bind(severity)
    .bind("ADMINISTRATOR")
    .bind(context.administrator_id.to_string())
    .bind("ENVIRONMENT")
    .bind(context.scope.environment.to_string())
    .bind(context.request_id)
    .bind(context.transition.from_configuration_version_id)
    .bind(context.transition.to_configuration_version_id)
    .bind(redacted_audit_data(data))
    .execute(&mut **tx)
    .await
    .map(|_| ())
    .map_err(|_| {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "audit_failure",
            "Failed to write audit record; operation rolled back",
            None,
            Some(context.request_id),
        )
    })
}

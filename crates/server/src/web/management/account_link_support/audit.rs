use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::audit_safety::redacted_audit_data;

use super::super::{error_response, ManagementEnvironmentScope};

pub(in crate::web::management) struct AccountLinkAuditEvent<'a> {
    pub(in crate::web::management) event_type: &'a str,
    pub(in crate::web::management) severity: &'a str,
    pub(in crate::web::management) target_id: &'a str,
    pub(in crate::web::management) data: serde_json::Value,
}

pub(in crate::web::management) async fn write_account_link_audit_event(
    tx: &mut Transaction<'_, Postgres>,
    scope: ManagementEnvironmentScope,
    administrator_id: Uuid,
    request_id: &str,
    event: AccountLinkAuditEvent<'_>,
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
    .bind(scope.team)
    .bind(scope.tenant)
    .bind(scope.environment)
    .bind(event.event_type)
    .bind("CONTROL_PLANE")
    .bind("SUCCESS")
    .bind(event.severity)
    .bind("ADMINISTRATOR")
    .bind(administrator_id.to_string())
    .bind("ACCOUNT_LINK")
    .bind(event.target_id)
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

use super::super::super::{error_response, ManagementTenantScope};
use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::audit_safety::redacted_audit_data;

pub(super) async fn write_environment_created_audit_event(
    tx: &mut Transaction<'_, Postgres>,
    scope: &ManagementTenantScope,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    issuer_host: &str,
    administrator_id: Uuid,
    request_id: &str,
) -> Result<(), Response> {
    let audit_data = serde_json::json!({
        "environmentId": environment_id.to_string(),
        "tenantId": scope.tenant.to_string(),
        "issuerHost": issuer_host,
    });
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
  to_configuration_version_id,
  data
)
VALUES ($1, $2, $3, $4, $5, $6, $7, now(), $8, $9, $10, $11, $12, $13, $14)
        ",
    )
    .bind(scope.team)
    .bind(scope.tenant)
    .bind(environment_id)
    .bind("ENVIRONMENT_CREATED")
    .bind("CONTROL_PLANE")
    .bind("SUCCESS")
    .bind("INFO")
    .bind("ADMINISTRATOR")
    .bind(administrator_id.to_string())
    .bind("ENVIRONMENT")
    .bind(environment_id.to_string())
    .bind(request_id)
    .bind(configuration_version_id)
    .bind(redacted_audit_data(audit_data))
    .execute(&mut **tx)
    .await
    .map(|_| ())
    .map_err(|_| {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "audit_failure",
            "Failed to write audit record; operation rolled back",
            None,
            Some(request_id),
        )
    })
}

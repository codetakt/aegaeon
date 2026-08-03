use axum::{http::StatusCode, response::Response};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::{
    error_response, management_internal_error, redacted_audit_data, ManagementEnvironmentScope,
};

pub(super) fn serialize_management_json<T: serde::Serialize>(
    value: &T,
    request_id: &str,
    message: &str,
) -> Result<serde_json::Value, Response> {
    serde_json::to_value(value).map_err(|_| management_internal_error(request_id, message))
}

pub(super) async fn begin_management_transaction<'a>(
    pool: &'a PgPool,
    request_id: &str,
) -> Result<Transaction<'a, Postgres>, Response> {
    pool.begin()
        .await
        .map_err(|_| management_internal_error(request_id, "Failed to start transaction"))
}

pub(super) async fn commit_management_transaction(
    tx: Transaction<'_, Postgres>,
    request_id: &str,
) -> Result<(), Response> {
    tx.commit()
        .await
        .map_err(|_| management_internal_error(request_id, "Failed to commit transaction"))
}

pub(super) struct ManagementControlPlaneAuditEvent<'a> {
    pub(super) scope: ManagementEnvironmentScope,
    pub(super) administrator_id: Uuid,
    pub(super) request_id: &'a str,
    pub(super) event_type: &'a str,
    pub(super) target_type: &'a str,
    pub(super) target_id: String,
    pub(super) data: serde_json::Value,
}

pub(super) async fn write_management_control_plane_audit_event(
    tx: &mut Transaction<'_, Postgres>,
    event: ManagementControlPlaneAuditEvent<'_>,
) -> Result<(), Response> {
    let request_id = event.request_id;
    let data = redacted_audit_data(event.data);
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
    .bind(event.scope.team)
    .bind(event.scope.tenant)
    .bind(event.scope.environment)
    .bind(event.event_type)
    .bind("CONTROL_PLANE")
    .bind("SUCCESS")
    .bind("INFO")
    .bind("ADMINISTRATOR")
    .bind(event.administrator_id.to_string())
    .bind(event.target_type)
    .bind(event.target_id)
    .bind(request_id)
    .bind(data)
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

#[cfg(test)]
mod tests {
    use super::redacted_audit_data;
    use serde_json::json;

    #[test]
    fn audit_data_is_redacted_before_persistence() {
        let data = redacted_audit_data(json!({
            "clientSecret": "plain",
            "nested": {
                "privateKeyPem": "pem",
                "public": "kept"
            }
        }));

        assert_eq!(data["clientSecret"], "[REDACTED]");
        assert_eq!(data["nested"]["privateKeyPem"], "[REDACTED]");
        assert_eq!(data["nested"]["public"], "kept");
    }
}

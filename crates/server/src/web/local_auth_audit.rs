use super::local_auth_support::local_auth_response;
use super::render_local_result_page;
use crate::local_credentials;
use axum::response::Response;
use http::StatusCode;
use serde_json::Value;
use sqlx::PgPool;

use crate::audit_safety::redacted_audit_data;

pub(super) struct LocalAuthAuditEvent<'a> {
    pub(super) environment: &'a local_credentials::RuntimeEnvironmentContext,
    pub(super) event_type: &'a str,
    pub(super) outcome: &'a str,
    pub(super) severity: &'a str,
    pub(super) actor_type: &'a str,
    pub(super) actor_id: Option<&'a str>,
    pub(super) target_type: &'a str,
    pub(super) target_id: Option<&'a str>,
    pub(super) request_id: &'a str,
    pub(super) data: Value,
}

pub(super) fn local_auth_audit_failure_response() -> Response {
    local_auth_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        render_local_result_page("Server error", "Failed to record audit event.", None),
    )
}

pub(super) async fn load_local_auth_audit_environment(
    pool: &PgPool,
    issuer: &str,
) -> Result<Option<local_credentials::RuntimeEnvironmentContext>, Response> {
    local_credentials::load_runtime_environment_context(pool, issuer)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "failed to load local authentication audit context");
            local_auth_audit_failure_response()
        })
}

pub(super) async fn write_local_auth_audit(
    pool: &PgPool,
    event: LocalAuthAuditEvent<'_>,
) -> Result<(), sqlx::Error> {
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
VALUES (
  $1, $2, $3, $4, 'authentication', $5, $6, now(),
  $7, $8, $9, $10, $11, $12
)
        ",
    )
    .bind(event.environment.team_id)
    .bind(event.environment.tenant_id)
    .bind(event.environment.environment_id)
    .bind(event.event_type)
    .bind(event.outcome)
    .bind(event.severity)
    .bind(event.actor_type)
    .bind(event.actor_id)
    .bind(event.target_type)
    .bind(event.target_id)
    .bind(event.request_id)
    .bind(redacted_audit_data(event.data))
    .execute(pool)
    .await
    .map(|_| ())
}

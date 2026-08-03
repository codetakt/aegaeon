use super::super::super::{
    audit_event_from_row_result, error_response, management_internal_error, redact_audit_event,
};
use super::super::scope::AuditScope;
use crate::management::types::AuditEvent;
use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;
use uuid::Uuid;

pub(in crate::web::management::audit_events) async fn fetch_audit_event(
    pool: &PgPool,
    scope: AuditScope,
    audit_event_id: Uuid,
    request_id: &str,
) -> Result<AuditEvent, Response> {
    let Ok(row) = sqlx::query(
        r#"
SELECT
  id, team_id, tenant_id, environment_id,
  event_type, category, outcome, severity,
  to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS occurred_at,
  actor_type, actor_id, host(ip_address)::text AS ip_address, user_agent, mfa,
  target_type, target_id,
  request_id, trace_id, span_id,
  from_configuration_version_id, to_configuration_version_id,
  json_patch, data
FROM aegaeon.audit_events
WHERE id = $1 AND team_id = $2
        "#,
    )
    .bind(audit_event_id)
    .bind(scope.team_id())
    .fetch_optional(pool)
    .await
    else {
        return Err(management_internal_error(
            request_id,
            "Database query failed",
        ));
    };

    let Some(row) = row else {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Audit event not found",
            None,
            Some(request_id),
        ));
    };

    let mut event = audit_event_from_row_result(&row, request_id)?;
    redact_audit_event(&mut event);
    Ok(event)
}

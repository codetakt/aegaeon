use serde_json::json;
use sqlx::PgPool;

use crate::audit_safety::redacted_audit_data;
use crate::upstream::UpstreamAuthRequest;

pub(in crate::web) async fn record_upstream_callback_session_failure_audit(
    pool: &PgPool,
    request: &UpstreamAuthRequest,
    user_id: &str,
    request_id: &str,
    reason: &str,
) {
    let context = request.managed_connection_context();
    if let Err(error) = sqlx::query(
        r"
INSERT INTO aegaeon.audit_events (
  team_id, tenant_id, environment_id, event_type, category, outcome, severity,
  occurred_at, actor_type, actor_id, target_type, target_id, request_id, data
)
VALUES ($1, $2, $3, 'upstream_auth_session_create_failed.v1', 'authentication', 'failure', 'error',
        now(), 'end_user', $4, 'connection', $5, $6, $7)
        ",
    )
    .bind(context.team_id)
    .bind(context.tenant_id)
    .bind(context.environment_id)
    .bind(user_id)
    .bind(context.connection_id.to_string())
    .bind(request_id)
    .bind(redacted_audit_data(json!({
        "phase": "post_database_commit",
        "reason": reason,
        "upstreamIssuer": request.issuer.as_str()
    })))
    .execute(pool)
    .await
    {
        tracing::warn!(
            error = %error,
            request_id,
            "failed to write upstream callback session failure audit event"
        );
    }
}

use super::super::oauth_errors::json_error_with_iss;
use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Transaction};

use crate::audit_safety::redacted_audit_data;
use crate::upstream::UpstreamAuthRequest;

pub(in crate::web) async fn record_upstream_callback_audit(
    tx: &mut Transaction<'_, Postgres>,
    request: &UpstreamAuthRequest,
    user_id: &str,
    issuer_base: &str,
    request_id: &str,
) -> Result<(), Response> {
    let context = request.managed_connection_context();
    sqlx::query(
        r"
INSERT INTO aegaeon.audit_events (
  team_id, environment_id, event_type, category, outcome, severity,
  occurred_at, actor_type, actor_id, target_type, target_id, request_id
)
VALUES ($1, $2, 'upstream_auth', 'authentication', 'success', 'info',
        now(), 'end_user', $3, 'connection', $4, $5)
        ",
    )
    .bind(context.team_id)
    .bind(context.environment_id)
    .bind(user_id)
    .bind(context.connection_id.to_string())
    .bind(request_id)
    .execute(&mut **tx)
    .await
    .map(|_| ())
    .map_err(|_| {
        json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some("failed to write upstream authentication audit event"),
            issuer_base,
        )
    })
}

pub(in crate::web) async fn record_upstream_account_link_audit(
    tx: &mut Transaction<'_, Postgres>,
    request: &UpstreamAuthRequest,
    user_id: &str,
    upstream_sub_hash: &str,
    event_type: &str,
    issuer_base: &str,
    request_id: &str,
) -> Result<(), Response> {
    let context = request.managed_connection_context();
    sqlx::query(
        r"
INSERT INTO aegaeon.audit_events (
  team_id, environment_id, event_type, category, outcome, severity,
  occurred_at, actor_type, actor_id, target_type, target_id, request_id, data
)
VALUES ($1, $2, $3, 'identity_link', 'success', 'info',
        now(), 'end_user', $4, 'account_link', $5, $6, $7)
        ",
    )
    .bind(context.team_id)
    .bind(context.environment_id)
    .bind(event_type)
    .bind(user_id)
    .bind(context.connection_id.to_string())
    .bind(request_id)
    .bind(redacted_audit_data(serde_json::json!({
        "upstreamIssuer": request.issuer.as_str(),
        "upstreamSubjectHash": upstream_sub_hash
    })))
    .execute(&mut **tx)
    .await
    .map(|_| ())
    .map_err(|_| {
        json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some("failed to write upstream account-link audit event"),
            issuer_base,
        )
    })
}

pub(in crate::web) async fn record_upstream_user_provision_audit(
    tx: &mut Transaction<'_, Postgres>,
    request: &UpstreamAuthRequest,
    subject: &str,
    event_type: &str,
    issuer_base: &str,
    request_id: &str,
) -> Result<(), Response> {
    let context = request.managed_connection_context();
    sqlx::query(
        r"
INSERT INTO aegaeon.audit_events (
  team_id, environment_id, event_type, category, outcome, severity,
  occurred_at, actor_type, actor_id, target_type, target_id, request_id, data
)
VALUES ($1, $2, $3, 'user_provisioning', 'authorized', 'info',
        now(), 'end_user', $4, 'end_user', $4, $5, $6)
        ",
    )
    .bind(context.team_id)
    .bind(context.environment_id)
    .bind(event_type)
    .bind(subject)
    .bind(request_id)
    .bind(redacted_audit_data(serde_json::json!({
        "upstreamIssuer": request.issuer.as_str(),
        "connectionId": context.connection_id.to_string()
    })))
    .execute(&mut **tx)
    .await
    .map(|_| ())
    .map_err(|_| {
        json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some("failed to write upstream user provisioning audit event"),
            issuer_base,
        )
    })
}

use axum::{http::StatusCode, response::Response};
use serde_json::Value;

use crate::audit_safety::redacted_audit_data;
use crate::local_credentials;

use super::oauth_errors::no_cache_json_error_with_iss;
use super::{AppState, TokenEndpointContext};

pub(super) struct OAuthAuditEvent<'a> {
    pub(super) event_type: &'a str,
    pub(super) category: &'a str,
    pub(super) outcome: &'a str,
    pub(super) severity: &'a str,
    pub(super) actor_type: &'a str,
    pub(super) actor_id: Option<&'a str>,
    pub(super) target_type: &'a str,
    pub(super) target_id: Option<&'a str>,
    pub(super) request_id: &'a str,
    pub(super) data: Value,
}

fn oauth_audit_failure_response(issuer_base: &str) -> Response {
    no_cache_json_error_with_iss(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        Some("failed to record audit event"),
        issuer_base,
    )
}

pub(super) async fn require_oauth_audit(
    state: &AppState,
    issuer_base: &str,
    event: OAuthAuditEvent<'_>,
) -> Result<(), Response> {
    let environment =
        local_credentials::load_runtime_environment_context(&state.db_pool, issuer_base)
            .await
            .map_err(|err| {
                tracing::error!(error = %err, "failed to load OAuth audit environment context");
                oauth_audit_failure_response(issuer_base)
            })?
            .ok_or_else(|| {
                tracing::error!("OAuth audit environment context was not found");
                oauth_audit_failure_response(issuer_base)
            })?;

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
  $1, $2, $3, $4, $5, $6, $7, now(),
  $8, $9, $10, $11, $12, $13
)
        ",
    )
    .bind(environment.team_id)
    .bind(environment.tenant_id)
    .bind(environment.environment_id)
    .bind(event.event_type)
    .bind(event.category)
    .bind(event.outcome)
    .bind(event.severity)
    .bind(event.actor_type)
    .bind(event.actor_id)
    .bind(event.target_type)
    .bind(event.target_id)
    .bind(event.request_id)
    .bind(redacted_audit_data(event.data))
    .execute(&state.db_pool)
    .await
    .map(|_| ())
    .map_err(|err| {
        tracing::error!(error = %err, "failed to write OAuth audit event");
        oauth_audit_failure_response(issuer_base)
    })
}

pub(super) async fn require_token_issue_audit(
    state: &AppState,
    issuer_base: &str,
    ctx: &TokenEndpointContext,
    subject: Option<&str>,
) -> Result<(), Response> {
    require_oauth_audit(
        state,
        issuer_base,
        OAuthAuditEvent {
            event_type: "oauth.token.issue.requested.v1",
            category: "token",
            outcome: "requested",
            severity: "info",
            actor_type: "client",
            actor_id: Some(ctx.client_id.as_str()),
            target_type: "oauth_grant",
            target_id: Some(ctx.grant_type.as_str()),
            request_id: ctx.request_id.as_str(),
            data: serde_json::json!({
                "grantType": ctx.grant_type.as_str(),
                "resource": ctx.resource.as_deref(),
                "subject": subject,
                "senderConstraint": format!("{:?}", ctx.sender_constraint),
                "refreshGrantAllowed": ctx.refresh_grant_allowed,
                "authorizationCodeGrantAllowed": ctx.authorization_code_grant_allowed
            }),
        },
    )
    .await
}

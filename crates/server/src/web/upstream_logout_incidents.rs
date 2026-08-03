mod audit;
mod model;
mod store;

use super::{no_cache_redirect_response, oauth_errors::no_cache_json_error_with_iss};
use crate::util;
use audit::{write_federation_logout_relay_audit, FederationLogoutRelayAuditEvent};
use axum::{http::StatusCode, response::Response};
use model::{UpstreamLogoutIncidentRecord, UpstreamLogoutIncidentStatus};
use serde_json::json;
use sqlx::PgPool;
use store::{
    load_upstream_logout_incident_by_hash, update_upstream_logout_incident_status,
    UpstreamLogoutIncidentTransition,
};

pub(super) use model::{hash_upstream_logout_secret, UpstreamLogoutIncidentRequest};
pub(super) use store::{
    create_upstream_logout_incident, load_active_logout_recovery_policy_for_connection,
};

pub(super) fn invalid_logout_relay_state_response(issuer_base: &str) -> Response {
    no_cache_json_error_with_iss(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        Some("logout relay state is invalid or expired"),
        issuer_base,
    )
}

async fn write_rejected_upstream_logout_callback_audit(
    pool: &PgPool,
    incident: &UpstreamLogoutIncidentRecord,
    request_id: &str,
) {
    write_federation_logout_relay_audit(
        pool,
        FederationLogoutRelayAuditEvent {
            team_id: incident.team_id,
            tenant_id: incident.tenant_id,
            environment_id: incident.environment_id,
            connection_id: incident.connection_id,
            event_type: "federation.upstreamLogoutRelay.callbackRejected.v1",
            outcome: "failure",
            severity: "warning",
            actor_type: "system",
            actor_id: None,
            request_id,
            data: json!({
                "incidentId": incident.id.to_string(),
                "upstreamIssuer": incident.upstream_issuer,
                "recoveryPolicy": incident.recovery_policy.as_str(),
                "status": incident.status.as_str(),
                "failureReason": "relay token was no longer pending",
            }),
        },
    )
    .await;
}

async fn process_persisted_logout_incident(
    pool: &PgPool,
    incident: UpstreamLogoutIncidentRecord,
    issuer_base: &str,
    request_id: &str,
) -> Response {
    match incident.status {
        UpstreamLogoutIncidentStatus::Pending if !incident.is_expired => {
            update_upstream_logout_incident_status(
                pool,
                &incident,
                request_id,
                UpstreamLogoutIncidentTransition {
                    next_status: UpstreamLogoutIncidentStatus::Completed,
                    failure_reason: None,
                    event_type: "federation.upstreamLogoutRelay.completed.v1",
                    outcome: "success",
                    severity: "info",
                },
            )
            .await;
            no_cache_redirect_response(&util::append_state(
                &incident.downstream_redirect_uri,
                incident.downstream_state.as_deref(),
            ))
        }
        UpstreamLogoutIncidentStatus::Pending => {
            update_upstream_logout_incident_status(
                pool,
                &incident,
                request_id,
                UpstreamLogoutIncidentTransition {
                    next_status: UpstreamLogoutIncidentStatus::Expired,
                    failure_reason: Some("relay timeout"),
                    event_type: "federation.upstreamLogoutRelay.expired.v1",
                    outcome: "failure",
                    severity: "warning",
                },
            )
            .await;
            invalid_logout_relay_state_response(issuer_base)
        }
        UpstreamLogoutIncidentStatus::Completed
        | UpstreamLogoutIncidentStatus::Expired
        | UpstreamLogoutIncidentStatus::CallbackRejected
        | UpstreamLogoutIncidentStatus::OperatorCleared => {
            write_rejected_upstream_logout_callback_audit(pool, &incident, request_id).await;
            invalid_logout_relay_state_response(issuer_base)
        }
    }
}

pub(super) async fn persisted_logout_incident_response_by_hash(
    pool: &PgPool,
    relay_token_hash: &str,
    issuer_base: &str,
    request_id: &str,
) -> Result<Option<Response>, Response> {
    let Some(incident) =
        load_upstream_logout_incident_by_hash(pool, relay_token_hash, issuer_base).await?
    else {
        return Ok(None);
    };
    Ok(Some(
        process_persisted_logout_incident(pool, incident, issuer_base, request_id).await,
    ))
}

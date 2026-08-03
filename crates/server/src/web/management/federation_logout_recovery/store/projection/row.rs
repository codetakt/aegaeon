use super::super::super::super::required_row_value;
use crate::management::types::FederationLogoutRecoveryIncident;
use axum::response::Response;
use sqlx::postgres::PgRow;
use uuid::Uuid;

fn federation_logout_recovery_incident_from_row(
    row: &PgRow,
    request_id: &str,
) -> Result<FederationLogoutRecoveryIncident, Response> {
    let message = "Failed to decode incident row";
    let id: Uuid = required_row_value(row, "id", request_id, message)?;
    let team_id: Uuid = required_row_value(row, "team_id", request_id, message)?;
    let tenant_id: Uuid = required_row_value(row, "tenant_id", request_id, message)?;
    let environment_id: Uuid = required_row_value(row, "environment_id", request_id, message)?;
    let connection_id: Option<Uuid> =
        required_row_value(row, "connection_id", request_id, message)?;
    let connection_identifier: Option<String> =
        required_row_value(row, "connection_identifier", request_id, message)?;
    let connection_name: Option<String> =
        required_row_value(row, "connection_name", request_id, message)?;
    let downstream_client_id: Option<String> =
        required_row_value(row, "downstream_client_id", request_id, message)?;
    let upstream_issuer: String = required_row_value(row, "upstream_issuer", request_id, message)?;
    let recovery_policy: String = required_row_value(row, "recovery_policy", request_id, message)?;
    let status: String = required_row_value(row, "status", request_id, message)?;
    let session_hint_claim: Option<String> =
        required_row_value(row, "session_hint_claim", request_id, message)?;
    let session_hint_present: bool =
        required_row_value(row, "session_hint_present", request_id, message)?;
    let downstream_redirect_uri: String =
        required_row_value(row, "downstream_redirect_uri", request_id, message)?;
    let downstream_state_present: bool =
        required_row_value(row, "downstream_state_present", request_id, message)?;
    let failure_reason: Option<String> =
        required_row_value(row, "failure_reason", request_id, message)?;
    let incident_request_id: String = required_row_value(row, "request_id", request_id, message)?;
    let created_at: String = required_row_value(row, "created_at", request_id, message)?;
    let expires_at: String = required_row_value(row, "expires_at", request_id, message)?;
    let resolved_at: Option<String> = required_row_value(row, "resolved_at", request_id, message)?;

    Ok(FederationLogoutRecoveryIncident {
        id: id.to_string(),
        team_id: team_id.to_string(),
        tenant_id: tenant_id.to_string(),
        environment_id: environment_id.to_string(),
        connection_id: connection_id.map(|value| value.to_string()),
        connection_identifier,
        connection_name,
        downstream_client_id,
        upstream_issuer,
        recovery_policy,
        status,
        session_hint_claim,
        session_hint_present,
        downstream_redirect_uri,
        downstream_state_present,
        failure_reason,
        request_id: incident_request_id,
        created_at,
        expires_at,
        resolved_at,
    })
}

pub(in crate::web::management::federation_logout_recovery) fn federation_logout_recovery_incident_from_row_result(
    row: &PgRow,
    request_id: &str,
) -> Result<FederationLogoutRecoveryIncident, Response> {
    federation_logout_recovery_incident_from_row(row, request_id)
}

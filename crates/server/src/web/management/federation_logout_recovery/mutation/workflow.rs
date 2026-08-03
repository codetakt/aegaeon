use super::super::super::{
    begin_management_transaction, commit_management_transaction, error_response,
    load_management_environment_record, require_team_lifecycle_role,
    require_team_lifecycle_role_in_transaction, write_management_control_plane_audit_event,
    ManagementControlPlaneAuditEvent,
};
use super::super::read::parse_incident_scope;
use super::super::store::{
    clear_federation_logout_recovery_incident_status,
    federation_logout_recovery_incident_from_row_result,
    federation_logout_recovery_incident_not_found, load_federation_logout_recovery_incident_row,
};
use crate::management::types::ClearFederationLogoutRecoveryIncidentRequest;
use crate::web::management::state::ManagementSession;
use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;

pub(super) async fn clear_federation_logout_recovery_incident_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentIncidentPath,
    req: &ClearFederationLogoutRecoveryIncidentRequest,
    session: &ManagementSession,
    request_id: &str,
) -> Result<(), Response> {
    let (team_id, environment_id, incident_id) = parse_incident_scope(params, request_id)?;
    let reason = req.reason.trim();
    if reason.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Clear reason is required",
            None,
            Some(request_id),
        ));
    }

    require_team_lifecycle_role(
        pool,
        team_id,
        session,
        request_id,
        "Insufficient permissions for incident remediation operations",
    )
    .await?;

    let environment =
        load_management_environment_record(pool, team_id, environment_id, request_id).await?;
    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        team_id,
        session,
        request_id,
        "Insufficient permissions for incident remediation operations",
    )
    .await?;
    let Some(row) = load_federation_logout_recovery_incident_row(
        &mut *tx,
        environment.scope,
        incident_id,
        true,
        request_id,
        "Failed to load incident",
    )
    .await?
    else {
        return Err(federation_logout_recovery_incident_not_found(request_id));
    };
    let incident = federation_logout_recovery_incident_from_row_result(&row, request_id)?;

    if !matches!(
        incident.status.as_str(),
        "pending" | "expired" | "callback_rejected"
    ) {
        return Err(error_response(
            StatusCode::CONFLICT,
            "conflict",
            "Incident is already resolved",
            None,
            Some(request_id),
        ));
    }

    clear_federation_logout_recovery_incident_status(&mut tx, incident_id, reason, request_id)
        .await?;
    let incident_id_text = incident.id.clone();
    let audit_data = serde_json::json!({
        "incidentId": incident.id,
        "connectionId": incident.connection_id,
        "connectionIdentifier": incident.connection_identifier,
        "upstreamIssuer": incident.upstream_issuer,
        "recoveryPolicy": incident.recovery_policy,
        "previousStatus": incident.status,
        "clearReason": reason,
    });
    if write_management_control_plane_audit_event(
        &mut tx,
        ManagementControlPlaneAuditEvent {
            scope: environment.scope,
            administrator_id: session.administrator_id,
            request_id,
            event_type: "management.federationBrokenSession.cleared.v1",
            target_type: "FEDERATION_LOGOUT_RECOVERY_INCIDENT",
            target_id: incident_id_text,
            data: audit_data,
        },
    )
    .await
    .is_err()
    {
        return Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "Audit write failed; operation aborted",
            None,
            Some(request_id),
        ));
    }
    commit_management_transaction(tx, request_id).await?;

    Ok(())
}

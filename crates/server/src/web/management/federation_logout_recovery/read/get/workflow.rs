use super::super::scope::parse_incident_scope;
use crate::management::types::FederationLogoutRecoveryIncident;
use crate::web::management::federation_logout_recovery::store::{
    federation_logout_recovery_incident_from_row_result,
    federation_logout_recovery_incident_not_found, load_federation_logout_recovery_incident_row,
};
use crate::web::management::state::ManagementSession;
use crate::web::management::{load_management_environment_record, require_team_audit_read_access};
use axum::response::Response;
use sqlx::PgPool;

pub(super) async fn get_federation_logout_recovery_incident_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentIncidentPath,
    session: &ManagementSession,
    request_id: &str,
) -> Result<FederationLogoutRecoveryIncident, Response> {
    let (team_id, environment_id, incident_id) = parse_incident_scope(params, request_id)?;
    require_team_audit_read_access(
        pool,
        team_id,
        session,
        request_id,
        "Insufficient permissions; incident read requires audit read access",
    )
    .await?;

    let environment =
        load_management_environment_record(pool, team_id, environment_id, request_id).await?;
    let Some(row) = load_federation_logout_recovery_incident_row(
        pool,
        environment.scope,
        incident_id,
        false,
        request_id,
        "Database query failed",
    )
    .await?
    else {
        return Err(federation_logout_recovery_incident_not_found(request_id));
    };

    federation_logout_recovery_incident_from_row_result(&row, request_id)
}

use uuid::Uuid;

use super::super::super::TeamEnvironmentIncidentPath;

pub(in crate::web::management::federation_logout_recovery) fn parse_incident_scope(
    params: &TeamEnvironmentIncidentPath,
    request_id: &str,
) -> Result<(Uuid, Uuid, Uuid), axum::response::Response> {
    params.ids(request_id)
}

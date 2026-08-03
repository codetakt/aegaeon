mod list;
mod lookup;
mod mutation;
mod projection;

use super::super::error_response;
use axum::{http::StatusCode, response::Response};

pub(super) use list::list_federation_logout_recovery_incident_rows;
pub(super) use lookup::load_federation_logout_recovery_incident_row;
pub(super) use mutation::clear_federation_logout_recovery_incident_status;
pub(super) use projection::federation_logout_recovery_incident_from_row_result;

pub(super) fn federation_logout_recovery_incident_not_found(request_id: &str) -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "Federation logout recovery incident not found",
        None,
        Some(request_id),
    )
}

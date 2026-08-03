mod filters;
mod mutation;
mod read;
mod store;

#[cfg(test)]
pub(super) use filters::{
    normalize_federation_logout_recovery_policy_filter,
    normalize_federation_logout_recovery_status_filter,
};

use super::AppState;
use axum::{
    routing::{get, post},
    Router,
};

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/teams/:teamId/environments/:environmentId/federationLogoutRecoveryIncidents",
            get(read::list_federation_logout_recovery_incidents),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/federationLogoutRecoveryIncidents/:incidentId",
            get(read::get_federation_logout_recovery_incident),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/federationLogoutRecoveryIncidents/:incidentId/clear",
            post(mutation::clear_federation_logout_recovery_incident),
        )
}

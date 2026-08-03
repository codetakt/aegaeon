use super::AppState;
use axum::{
    routing::{get, post},
    Router,
};

mod audit;
mod mutation;
mod policy;
mod policy_patch;
mod read;

use mutation::{
    activate_configuration_version, archive_configuration_version, create_configuration_version,
};
use policy::patch_policies;
use read::{get_configuration_version, get_policies, list_configuration_versions};

#[cfg(test)]
pub(in crate::web::management) use read::FETCH_CONFIGURATION_VERSION_ROW_SQL;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/teams/:teamId/environments/:environmentId/configurationVersions",
            get(list_configuration_versions).post(create_configuration_version),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/configurationVersions/:configurationVersionId",
            get(get_configuration_version),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/configurationVersions/:configurationVersionId/activate",
            post(activate_configuration_version),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/configurationVersions/:configurationVersionId/archive",
            post(archive_configuration_version),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/policies",
            get(get_policies).patch(patch_policies),
        )
}

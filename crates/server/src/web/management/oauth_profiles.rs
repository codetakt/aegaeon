use super::AppState;
use axum::{routing::get, Router};

mod audit;
mod mutation;
mod query;
mod read;

use mutation::{create_oauth_profile, delete_oauth_profile, update_oauth_profile};
pub(in crate::web::management) use read::get_oauth_profile_inner;
use read::{get_oauth_profile, list_oauth_profiles};

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/teams/:teamId/environments/:environmentId/oauthProfiles",
            get(list_oauth_profiles).post(create_oauth_profile),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/oauthProfiles/:oauthProfileId",
            get(get_oauth_profile)
                .patch(update_oauth_profile)
                .delete(delete_oauth_profile),
        )
}

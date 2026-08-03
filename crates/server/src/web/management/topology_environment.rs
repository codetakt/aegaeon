mod mutation;
mod read;

pub(super) use mutation::create_environment;
pub(in crate::web::management) use read::get_environment_inner;
pub(super) use read::list_environments;

use super::AppState;
use axum::{routing::get, Router};

pub(super) fn environment_identity_routes() -> Router<AppState> {
    Router::new().route(
        "/teams/:teamId/environments/:environmentId",
        get(read::get_environment)
            .patch(mutation::update_environment)
            .delete(mutation::delete_environment),
    )
}

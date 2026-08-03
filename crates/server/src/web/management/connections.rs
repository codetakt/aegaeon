mod mutation;
mod policy_boundary;
mod preparation;
mod query;
mod read;
pub(in crate::web::management) use read::get_connection_inner;

use super::AppState;
use axum::{routing::get, Router};

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/teams/:teamId/environments/:environmentId/connections",
            get(read::list_connections).post(mutation::create_connection),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/connections/:connectionId",
            get(read::get_connection)
                .patch(mutation::update_connection)
                .delete(mutation::delete_connection),
        )
}

use super::AppState;
use axum::{routing::get, Router};

mod mutation;
mod policy_boundary;
mod preparation;
mod read;

use mutation::{create_client, delete_client, update_client};
pub(in crate::web::management) use read::get_client_inner;
use read::{get_client, list_clients};

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/teams/:teamId/environments/:environmentId/clients",
            get(list_clients).post(create_client),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/clients/:clientId",
            get(get_client).patch(update_client).delete(delete_client),
        )
}

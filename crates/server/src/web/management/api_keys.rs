use super::AppState;
use axum::{
    routing::{get, post},
    Router,
};

mod audit;
mod handlers;
mod input;
mod store;

use handlers::{create_api_key, list_api_keys, revoke_api_key};

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/teams/:teamId/apiKeys",
            get(list_api_keys).post(create_api_key),
        )
        .route(
            "/teams/:teamId/apiKeys/:apiKeyId/revoke",
            post(revoke_api_key),
        )
}

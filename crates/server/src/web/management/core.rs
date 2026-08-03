mod authentication;
mod bootstrap;
mod system;

use axum::{
    routing::{delete, get, post},
    Router,
};

use super::AppState;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/system/health", get(system::system_health))
        .route("/system/version", get(system::system_version))
        .route(
            "/authentication/sessions",
            post(authentication::create_authentication_session),
        )
        .route(
            "/authentication/sessions/current",
            delete(authentication::delete_current_authentication_session),
        )
        .route("/bootstrapping/owners", post(bootstrap::bootstrap_owner))
}

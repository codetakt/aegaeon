use super::AppState;
use axum::{
    routing::{get, post},
    Router,
};

mod audit;
mod create;
mod input;
mod lifecycle;
mod list;

#[cfg(test)]
pub(super) use audit::{runtime_key_create_audit_data, runtime_key_lifecycle_audit_data};
use create::create_runtime_key;
#[cfg(test)]
pub(super) use create::create_runtime_key_inner;
#[cfg(test)]
pub(super) use input::{prepare_runtime_key_create_input, prepare_runtime_key_create_input_async};
pub(super) use input::{runtime_key_bad_request, RuntimeKeyCreateInput, RuntimeKeyUsageInput};
use lifecycle::{activate_next_runtime_key, revoke_runtime_key};
#[cfg(test)]
pub(super) use lifecycle::{activate_next_runtime_key_inner, revoke_runtime_key_inner};
use list::list_runtime_keys;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/teams/:teamId/environments/:environmentId/runtimeKeys",
            get(list_runtime_keys).post(create_runtime_key),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/runtimeKeys/activateNext",
            post(activate_next_runtime_key),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/runtimeKeys/:runtimeKeyId/revoke",
            post(revoke_runtime_key),
        )
}

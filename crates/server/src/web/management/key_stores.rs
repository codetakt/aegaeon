mod audit;
mod mutation;
mod read;
mod store;
mod validation;
pub(in crate::web::management) use read::get_key_store_inner;

#[cfg(test)]
pub(super) use store::LOAD_KEY_STORE_ROW_SQL;
#[cfg(test)]
pub(super) use validation::validate_key_store_update_request;
pub(super) use validation::{
    key_store_public_config_contains_sensitive_key, normalize_key_store_audit_note,
    normalize_key_store_type, validate_key_store_public_configuration,
};

use super::AppState;
use axum::{routing::get, Router};

pub(super) fn routes() -> Router<AppState> {
    Router::new().route(
        "/teams/:teamId/environments/:environmentId/keyStores/current",
        get(read::get_key_store).put(mutation::update_key_store),
    )
}

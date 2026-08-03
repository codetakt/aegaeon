mod handlers;
mod store;
mod validation;

use axum::Router;

use super::AppState;

pub(super) use store::{
    delete_dcr_bearer_token_inner, load_dcr_bearer_token_status, set_dcr_bearer_token_inner,
};
pub(super) use validation::validate_dcr_bearer_token;

pub(super) fn routes() -> Router<AppState> {
    handlers::routes()
}

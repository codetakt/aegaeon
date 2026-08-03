mod delete;
mod read;
mod set;

use axum::{routing::get, Router};

use crate::web::management::AppState;

pub(super) fn routes() -> Router<AppState> {
    Router::new().route(
        "/teams/:teamId/environments/:environmentId/dcrBearerToken",
        get(read::get_dcr_bearer_token_status)
            .put(set::set_dcr_bearer_token)
            .delete(delete::delete_dcr_bearer_token),
    )
}

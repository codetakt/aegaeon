use axum::{Extension, Json};

use crate::management::types::SystemVersionResponse;

use super::super::RequestContext;

pub(super) async fn system_health() -> &'static str {
    "OK"
}

pub(super) async fn system_version(
    Extension(_ctx): Extension<RequestContext>,
) -> Json<SystemVersionResponse> {
    let version = env!("CARGO_PKG_VERSION").to_string();
    let commit = option_env!("GIT_COMMIT").map(ToString::to_string);
    Json(SystemVersionResponse { version, commit })
}

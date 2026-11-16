use crate::web::management::http_errors::management_session_error;
use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use crate::web::management::{build_session_set_cookie, management_internal_error, AppState};
use crate::web::now_epoch_secs;

pub(in crate::web::management::core::authentication::create::workflow) async fn create_management_session_response(
    state: &AppState,
    administrator_id: Uuid,
    request_id: &str,
) -> Response {
    let now_epoch_secs = match now_epoch_secs() {
        Ok(now) => now,
        Err(_) => {
            return management_internal_error(request_id, "System clock unavailable");
        }
    };
    let sid = match state
        .management
        .sessions
        .try_create_for_request(administrator_id, now_epoch_secs, request_id)
        .await
    {
        Ok(Some(sid)) => sid,
        Ok(None) => {
            return management_internal_error(request_id, "Failed to create session");
        }
        Err(err) => return management_session_error(request_id, &err),
    };

    let mut resp = StatusCode::NO_CONTENT.into_response();
    if let Ok(cookie) = HeaderValue::from_str(&build_session_set_cookie(
        &sid,
        state.management.cfg.cookie_secure,
        state.management.cfg.session_ttl_secs,
    )) {
        resp.headers_mut().append(header::SET_COOKIE, cookie);
    }
    resp
}

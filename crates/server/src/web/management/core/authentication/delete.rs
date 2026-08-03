use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Extension,
};

use super::super::super::{
    build_session_clear_cookie, error_response, get_management_session_id, AppState, RequestContext,
};

pub(in crate::web::management::core) async fn delete_current_authentication_session(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
) -> Response {
    let sid = match get_management_session_id(&headers, ctx.request_id.as_str()) {
        Ok(Some(sid)) => sid,
        Ok(None) => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "Session cookie required",
                None,
                Some(ctx.request_id.as_str()),
            );
        }
        Err(resp) => return resp,
    };

    if let Err(err) = state.management.sessions.try_delete_async(sid).await {
        tracing::error!(
            error=%err,
            request_id=%ctx.request_id,
            "management session store delete failed during logout"
        );
        let mut resp = error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "Failed to delete session",
            None,
            Some(ctx.request_id.as_str()),
        );
        if let Ok(cookie) = HeaderValue::from_str(&build_session_clear_cookie(
            state.management.cfg.cookie_secure,
        )) {
            resp.headers_mut().append(header::SET_COOKIE, cookie);
        }
        return resp;
    }

    let mut resp = StatusCode::NO_CONTENT.into_response();
    if let Ok(cookie) = HeaderValue::from_str(&build_session_clear_cookie(
        state.management.cfg.cookie_secure,
    )) {
        resp.headers_mut().append(header::SET_COOKIE, cookie);
    }
    resp
}

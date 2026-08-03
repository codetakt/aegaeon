use super::super::{
    apply_auth_session_clear_cookie, auth_session_store_logout_error_response,
    build_upstream_logout_redirect_target_with_relay, cookie_value,
    local_logout_redirect_target_with_policy, no_cache_header_error, request_id_from_headers,
    single_cookie_header, AppState, AUTH_SESSION_COOKIE_NAME,
};
use crate::util;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use http::{header, HeaderMap, HeaderValue, StatusCode};

pub(in crate::web) async fn local_logout_post(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let mut redirect_target = "/auth/login".to_string();
    let request_id = request_id_from_headers(&headers);
    let cookie_header = match single_cookie_header(&headers) {
        Ok(cookie_header) => cookie_header,
        Err(err) => return no_cache_header_error(state.issuer.as_str(), "Cookie", err),
    };
    if let Some(cookie_header) = cookie_header {
        if let Some(session_id) = cookie_value(cookie_header, AUTH_SESSION_COOKIE_NAME) {
            let session = match state
                .browser_auth
                .auth_sessions
                .try_get_async(session_id.clone())
                .await
            {
                Ok(session) => session,
                Err(err) => {
                    return auth_session_store_logout_error_response(state.issuer.as_str(), &err);
                }
            };
            redirect_target = match session.as_ref() {
                Some(session_record) => match session_record.upstream_logout.as_ref() {
                    Some(upstream_logout) => {
                        let allowed_domains = state.cfg.upstream().outbound_allowed_domains();
                        match build_upstream_logout_redirect_target_with_relay(
                            &state,
                            upstream_logout,
                            None,
                            "/auth/login",
                            None,
                            Some(session_record.user_id.as_str()),
                            &request_id,
                        )
                        .await
                        {
                            Ok(Some(target)) => target,
                            Ok(None) => local_logout_redirect_target_with_policy(
                                Some(session_record),
                                allowed_domains,
                            ),
                            Err(response) => return response,
                        }
                    }
                    None => local_logout_redirect_target_with_policy(
                        Some(session_record),
                        state.cfg.upstream().outbound_allowed_domains(),
                    ),
                },
                None => "/auth/login".to_string(),
            };
            if let Err(err) = state
                .browser_auth
                .auth_sessions
                .try_delete_async(session_id)
                .await
            {
                return auth_session_store_logout_error_response(state.issuer.as_str(), &err);
            }
        }
    }

    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&redirect_target)
            .unwrap_or_else(|_| HeaderValue::from_static("/auth/login")),
    );
    apply_auth_session_clear_cookie(&mut response);
    util::apply_no_cache_headers(&mut response);
    response
}

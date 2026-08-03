use axum::{
    extract::State,
    http::{header, HeaderValue, Method},
    middleware::Next,
    response::Response,
};

use crate::web::cookie_value;
use crate::web::management::security::{
    build_csrf_set_cookie, enforce_empty_management_delete_body, enforce_json_content_type,
    enforce_management_csrf, enforce_management_json_body_admission, generate_csrf_token,
    is_write_method,
};
use crate::web::management::session_support::management_bearer_api_key;
use crate::web::management::{
    error_response, insert_request_id_header, management_internal_error, management_single_header,
    ManagementState, CSRF_COOKIE_NAME,
};

use super::context::{request_id_from_headers, RequestContext};

pub(in crate::web::management) async fn management_security_middleware(
    State(mgmt): State<ManagementState>,
    mut req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let request_id = request_id_from_headers(req.headers());
    req.extensions_mut().insert(RequestContext {
        request_id: request_id.clone(),
    });

    if req.method() == Method::OPTIONS {
        let mut resp = next.run(req).await;
        insert_request_id_header(resp.headers_mut(), &request_id);
        return resp;
    }

    let api_key_request = match management_bearer_api_key(req.headers(), &request_id) {
        Ok(api_key) => api_key.is_some(),
        Err(resp) => return resp,
    };

    let cookies = match management_single_header(
        req.headers(),
        header::COOKIE.as_str(),
        "Cookie",
        &request_id,
    ) {
        Ok(cookies) => cookies,
        Err(resp) => return resp,
    };

    if api_key_request && cookies.is_some() {
        return error_response(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_request",
            "Management API key requests must not include Cookie",
            None,
            Some(&request_id),
        );
    }

    let (csrf_token, need_set_csrf_cookie) = if api_key_request {
        (None, false)
    } else {
        match cookies.and_then(|c| cookie_value(c, CSRF_COOKIE_NAME)) {
            Some(token) => (Some(token), false),
            None => match generate_csrf_token() {
                Ok(token) => (Some(token), true),
                Err(()) => {
                    return management_internal_error(&request_id, "Failed to generate CSRF token");
                }
            },
        }
    };

    if is_write_method(req.method()) {
        if let Some(csrf_token) = csrf_token.as_deref() {
            if let Err(resp) =
                enforce_management_csrf(req.headers(), csrf_token, &mgmt, &request_id)
            {
                return resp;
            }
        }
        if matches!(req.method(), &Method::POST | &Method::PUT | &Method::PATCH) {
            if let Err(resp) = enforce_json_content_type(req.headers(), &request_id) {
                return resp;
            }
            req = match enforce_management_json_body_admission(req, &request_id).await {
                Ok(req) => req,
                Err(resp) => return resp,
            };
        } else if req.method() == Method::DELETE {
            req = match enforce_empty_management_delete_body(req, &request_id).await {
                Ok(req) => req,
                Err(resp) => return resp,
            };
        }
    }

    let mut resp = next.run(req).await;
    insert_request_id_header(resp.headers_mut(), &request_id);
    crate::util::apply_no_cache_headers(&mut resp);
    if need_set_csrf_cookie {
        if let Some(csrf_token) = csrf_token.as_deref() {
            if let Ok(value) =
                HeaderValue::from_str(&build_csrf_set_cookie(csrf_token, mgmt.cfg.cookie_secure))
            {
                resp.headers_mut().append(header::SET_COOKIE, value);
            }
        }
    }
    resp
}

use super::form_helpers::{form_parse_error_response, singleton_form_field};
use super::oauth_errors::{
    apply_oauth_authenticate_header, authorization_header, bearer_header_error,
    bearer_json_error_with_iss, dpop_invalid_token_response, no_cache_json_error_with_iss,
};
use super::request_admission::{enforce_content_type, enforce_no_credentials_in_uri};
use super::{
    dpop_binding_from_request, transport_rejection, trusted_mtls_fingerprint, AppState,
    X_FORWARDED_CLIENT_CERT_HEADER,
};
use axum::{
    extract::{ConnectInfo, OriginalUri, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
    Json,
};
use std::net::SocketAddr;

use crate::middleware::DpopBinding;
use crate::util;

pub(super) async fn userinfo_get(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let issuer_base = state.issuer.as_str();
    let endpoint = match state.oidc.userinfo_endpoint.as_ref() {
        Some(ep) => ep.clone(),
        None => {
            return no_cache_json_error_with_iss(
                StatusCode::NOT_FOUND,
                "not_found",
                None,
                issuer_base,
            );
        }
    };
    if let Err(kind) = state.transport.enforce(Some(remote), &headers) {
        return transport_rejection(&state, kind);
    }
    if let Err(resp) = enforce_no_credentials_in_uri(&uri, issuer_base) {
        return resp;
    }

    let auth_header = match authorization_header(&headers) {
        Ok(header) => match header {
            Some(header) if !header.trim().is_empty() => header.to_string(),
            _ => {
                return bearer_json_error_with_iss(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    Some("authorization header required"),
                    issuer_base,
                );
            }
        },
        Err(err) => return bearer_header_error(issuer_base, "Authorization", err),
    };

    let path = uri
        .path_and_query()
        .map_or(uri.path(), axum::http::uri::PathAndQuery::as_str);
    let uri_for_dpop: Uri = match path.parse() {
        Ok(uri) => uri,
        Err(_) => return dpop_invalid_token_response(issuer_base, "DPoP proof validation failed"),
    };
    let binding = match dpop_binding_from_request(
        state.dpop.as_ref(),
        &http::Method::GET,
        &uri_for_dpop,
        &headers,
        issuer_base,
    ) {
        Ok(binding) => binding,
        Err(resp) => return resp,
    };

    let mtls = match trusted_mtls_fingerprint(&state, &headers) {
        Ok(mtls) => mtls,
        Err(err) => return bearer_header_error(issuer_base, X_FORWARDED_CLIENT_CERT_HEADER, err),
    };

    match endpoint
        .fetch_userinfo(&auth_header, binding.as_ref(), mtls.as_deref())
        .await
    {
        Ok(userinfo) => {
            let mut response = (StatusCode::OK, Json(userinfo)).into_response();
            util::apply_no_cache_headers(&mut response);
            response
        }
        Err(err) => userinfo_error_response(
            err,
            issuer_base,
            userinfo_challenge_scheme(&auth_header, binding.as_ref()),
        ),
    }
}

#[derive(Default)]
pub(super) struct UserinfoForm {
    access_token: Option<String>,
}

pub(super) fn parse_userinfo_form(
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
    issuer_base: &str,
) -> Result<UserinfoForm, Response> {
    let params = form
        .map(|axum::extract::Form(params)| params)
        .map_err(|_| form_parse_error_response(issuer_base))?;
    Ok(UserinfoForm {
        access_token: singleton_form_field(&params, "access_token", issuer_base)?,
    })
}

fn userinfo_auth_header(
    headers: &HeaderMap,
    form: &UserinfoForm,
    issuer_base: &str,
) -> Result<String, Response> {
    let header = authorization_header(headers)
        .map_err(|err| bearer_header_error(issuer_base, "Authorization", err))?
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let body_token = form
        .access_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match (header, body_token) {
        (Some(_), Some(_)) => Err(bearer_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("access token must not be supplied via multiple transport methods"),
            issuer_base,
        )),
        (Some(header), None) => Ok(header.to_string()),
        (None, Some(token)) => Ok(format!("Bearer {token}")),
        (None, None) => Err(bearer_json_error_with_iss(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            Some("authorization header or access_token required"),
            issuer_base,
        )),
    }
}

fn userinfo_challenge_scheme(
    auth_header: &str,
    dpop_binding: Option<&DpopBinding>,
) -> &'static str {
    let scheme_is_dpop = auth_header
        .split_whitespace()
        .next()
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("DPoP"));
    if scheme_is_dpop || dpop_binding.is_some() {
        "DPoP"
    } else {
        "Bearer"
    }
}

pub(super) fn userinfo_error_response(
    err: crate::oidc::userinfo::Error,
    issuer_base: &str,
    challenge_scheme: &'static str,
) -> Response {
    let (status, error_code, description) = match err {
        crate::oidc::userinfo::Error::InvalidToken => {
            (StatusCode::UNAUTHORIZED, "invalid_token", None)
        }
        crate::oidc::userinfo::Error::InsufficientScope => {
            (StatusCode::FORBIDDEN, "insufficient_scope", None)
        }
        crate::oidc::userinfo::Error::InvalidRequest(message) => {
            (StatusCode::BAD_REQUEST, "invalid_request", Some(message))
        }
        crate::oidc::userinfo::Error::ServerError(message) => {
            tracing::error!(
                target: "userinfo",
                error = %message,
                "userinfo request failed internally"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                Some("userinfo endpoint failed internally".to_string()),
            )
        }
    };
    let mut body = serde_json::json!({ "error": error_code, "iss": issuer_base });
    if let Some(description) = description {
        body["error_description"] = serde_json::json!(description);
    }
    let mut response = (status, Json(body)).into_response();
    if matches!(
        error_code,
        "invalid_token" | "insufficient_scope" | "invalid_request"
    ) {
        apply_oauth_authenticate_header(&mut response, challenge_scheme, error_code);
    }
    util::apply_no_cache_headers(&mut response);
    response
}

pub(super) async fn userinfo_post(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
) -> Response {
    let issuer_base = state.issuer.as_str();
    let endpoint = match state.oidc.userinfo_endpoint.as_ref() {
        Some(ep) => ep.clone(),
        None => {
            return no_cache_json_error_with_iss(
                StatusCode::NOT_FOUND,
                "not_found",
                None,
                issuer_base,
            );
        }
    };
    if let Err(kind) = state.transport.enforce(Some(remote), &headers) {
        return transport_rejection(&state, kind);
    }

    if let Err(resp) = enforce_no_credentials_in_uri(&uri, issuer_base) {
        return resp;
    }
    if let Err(resp) =
        enforce_content_type(&headers, "application/x-www-form-urlencoded", issuer_base)
    {
        return resp;
    }
    let form = match parse_userinfo_form(form, issuer_base) {
        Ok(form) => form,
        Err(resp) => return resp,
    };

    let auth_header = match userinfo_auth_header(&headers, &form, issuer_base) {
        Ok(header) => header,
        Err(response) => return response,
    };

    let path = uri
        .path_and_query()
        .map_or(uri.path(), axum::http::uri::PathAndQuery::as_str);
    let uri_for_dpop: Uri = match path.parse() {
        Ok(uri) => uri,
        Err(_) => return dpop_invalid_token_response(issuer_base, "DPoP proof validation failed"),
    };
    let binding = match dpop_binding_from_request(
        state.dpop.as_ref(),
        &http::Method::POST,
        &uri_for_dpop,
        &headers,
        issuer_base,
    ) {
        Ok(binding) => binding,
        Err(resp) => return resp,
    };

    let mtls = match trusted_mtls_fingerprint(&state, &headers) {
        Ok(mtls) => mtls,
        Err(err) => return bearer_header_error(issuer_base, X_FORWARDED_CLIENT_CERT_HEADER, err),
    };

    match endpoint
        .fetch_userinfo(&auth_header, binding.as_ref(), mtls.as_deref())
        .await
    {
        Ok(userinfo) => {
            let mut response = (StatusCode::OK, Json(userinfo)).into_response();
            util::apply_no_cache_headers(&mut response);
            response
        }
        Err(err) => userinfo_error_response(
            err,
            issuer_base,
            userinfo_challenge_scheme(&auth_header, binding.as_ref()),
        ),
    }
}

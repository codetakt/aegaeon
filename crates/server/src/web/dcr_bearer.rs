use super::oauth_errors::{
    apply_oauth_authenticate_header, authorization_header, bearer_json_error_with_iss,
};
use super::request_admission::{
    validate_uri_credentials, QueryCredentialPolicy, UriCredentialRejection,
};
use super::AppState;
use crate::util;
use axum::{
    extract::MatchedPath,
    http::{header, HeaderMap, HeaderValue, Method, Uri},
    response::{IntoResponse, Response},
};
use http::StatusCode;

enum RegistrationBearerHeader<'a> {
    NoAuthentication,
    Malformed,
    Token(&'a str),
}

fn classify_header(headers: &HeaderMap) -> RegistrationBearerHeader<'_> {
    let value = match authorization_header(headers) {
        Ok(Some(value)) => value,
        Ok(None) => return RegistrationBearerHeader::NoAuthentication,
        Err(_) => return RegistrationBearerHeader::Malformed,
    };
    let mut parts = value.split_whitespace();
    let Some(scheme) = parts.next() else {
        return RegistrationBearerHeader::NoAuthentication;
    };
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return RegistrationBearerHeader::NoAuthentication;
    }
    match (parts.next(), parts.next()) {
        (Some(token), None) => RegistrationBearerHeader::Token(token),
        _ => RegistrationBearerHeader::Malformed,
    }
}

fn authentication_required_response() -> Response {
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"aegaeon\""),
    );
    util::apply_no_cache_headers(&mut response);
    response
}

pub(super) fn registration_bearer_token<'a>(
    headers: &'a HeaderMap,
    issuer_base: &str,
) -> Result<&'a str, Response> {
    match classify_header(headers) {
        RegistrationBearerHeader::NoAuthentication => Err(authentication_required_response()),
        RegistrationBearerHeader::Malformed => Err(bearer_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("malformed Authorization header"),
            issuer_base,
        )),
        RegistrationBearerHeader::Token(token) => Ok(token),
    }
}

pub(super) fn require_registration_bearer(
    expected_hash: Option<&str>,
    headers: &HeaderMap,
    issuer_base: &str,
) -> Result<(), Response> {
    let Some(expected_hash) = expected_hash else {
        return Ok(());
    };
    let token = registration_bearer_token(headers, issuer_base)?;
    let token_hash = crate::dcr_persistence::dcr_bearer_token_hash(token);
    if util::constant_time_eq(token_hash.as_bytes(), expected_hash.as_bytes()) {
        Ok(())
    } else {
        Err(bearer_json_error_with_iss(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            Some("invalid initial access token"),
            issuer_base,
        ))
    }
}

pub(super) fn query_rejection_response(
    error: UriCredentialRejection,
    issuer_base: &str,
    bearer_required: bool,
) -> Response {
    let mut response = error.response(issuer_base);
    if bearer_required && error == UriCredentialRejection::AccessToken {
        apply_oauth_authenticate_header(&mut response, "Bearer", "invalid_request");
    }
    response
}

pub(super) fn enforce_dcr_query_admission(
    uri: &Uri,
    issuer_base: &str,
    bearer_required: bool,
) -> Result<(), Response> {
    validate_uri_credentials(uri, QueryCredentialPolicy::reject_all())
        .map_err(|error| query_rejection_response(error, issuer_base, bearer_required))
}

pub(super) fn requires_bearer_for_matched_route(
    state: &AppState,
    method: &Method,
    matched_path: Option<&MatchedPath>,
) -> bool {
    if !state.dcr_enabled {
        return false;
    }
    match (method, matched_path.map(MatchedPath::as_str)) {
        (&Method::POST, Some("/register")) => state.dcr_required_bearer_hash.is_some(),
        (
            &Method::GET | &Method::HEAD | &Method::PUT | &Method::DELETE,
            Some("/register/:client_id"),
        ) => true,
        _ => false,
    }
}

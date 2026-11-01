//! Resource-side presentation and early refusal envelopes; no proof or token work.
use super::oauth_errors::{
    apply_oauth_authenticate_header, authorization_header, no_cache_json_error_with_iss,
};
use super::request_admission::{
    validate_uri_credentials, QueryCredentialPolicy, UriCredentialRejection,
};
use super::AppState;
use crate::resource_authentication::{
    classify_resource_presentation, ResourceCredentials, ResourcePresentation, ResourceScheme,
};
use axum::{
    extract::MatchedPath,
    http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};

pub(super) fn no_resource_authentication() -> Response {
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"aegaeon\""),
    );
    crate::util::apply_no_cache_headers(&mut response);
    response
}

pub(super) fn resource_invalid_request(
    issuer: &str,
    scheme: ResourceScheme,
    description: &str,
) -> Response {
    let mut response = no_cache_json_error_with_iss(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        Some(description),
        issuer,
    );
    apply_oauth_authenticate_header(&mut response, scheme.as_str(), "invalid_request");
    response
}

pub(super) fn admit_resource_presentation<'a>(
    header: Option<&'a str>,
    issuer: &str,
) -> Result<ResourceCredentials<'a>, Response> {
    match classify_resource_presentation(header) {
        ResourcePresentation::Missing | ResourcePresentation::Unsupported => {
            Err(no_resource_authentication())
        }
        ResourcePresentation::Malformed(scheme) => Err(resource_invalid_request(
            issuer,
            scheme,
            "malformed authorization header",
        )),
        ResourcePresentation::Credentials(credentials) => Ok(credentials),
    }
}

pub(super) fn presented_resource_scheme(headers: &HeaderMap) -> ResourceScheme {
    match authorization_header(headers)
        .ok()
        .flatten()
        .map(|value| classify_resource_presentation(Some(value)))
    {
        Some(
            ResourcePresentation::Credentials(ResourceCredentials { scheme, .. })
            | ResourcePresentation::Malformed(scheme),
        ) => scheme,
        _ => ResourceScheme::Bearer,
    }
}

pub(super) fn resource_request_error(mut response: Response, headers: &HeaderMap) -> Response {
    apply_oauth_authenticate_header(
        &mut response,
        presented_resource_scheme(headers).as_str(),
        "invalid_request",
    );
    crate::util::apply_no_cache_headers(&mut response);
    response
}

pub(super) fn resource_uri_rejection(
    error: UriCredentialRejection,
    issuer: &str,
    headers: &HeaderMap,
) -> Response {
    let response = error.response(issuer);
    if error == UriCredentialRejection::AccessToken {
        resource_request_error(response, headers)
    } else {
        response
    }
}

pub(super) fn enforce_resource_uri(
    uri: &Uri,
    issuer: &str,
    headers: &HeaderMap,
) -> Result<(), Response> {
    validate_uri_credentials(uri, QueryCredentialPolicy::reject_all())
        .map_err(|error| resource_uri_rejection(error, issuer, headers))
}

pub(super) fn protected_resource_matched_route(
    state: &AppState,
    method: &Method,
    matched: Option<&MatchedPath>,
) -> bool {
    match (method, matched.map(MatchedPath::as_str)) {
        (&Method::GET | &Method::HEAD, Some("/resource" | "/application/authorization")) => true,
        (&Method::GET | &Method::HEAD | &Method::POST, Some("/userinfo")) => {
            state.oidc.userinfo_endpoint.is_some()
        }
        (&Method::POST, Some("/oauth/upstream/refresh")) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests;

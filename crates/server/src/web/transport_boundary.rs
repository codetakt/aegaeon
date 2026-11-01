use super::dcr_bearer::{query_rejection_response, requires_bearer_for_matched_route};
use super::request_admission::{uri_credential_policy_for_request, validate_uri_credentials};
use super::AppState;
use crate::middleware::tls::TransportRejectionKind;
use crate::util;
use axum::{
    body::Body,
    extract::{ConnectInfo, MatchedPath, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use std::net::SocketAddr;

pub(super) async fn transport_security_middleware(
    State(state): State<AppState>,
    mut req: axum::http::Request<Body>,
    next: Next,
) -> Response {
    if should_enforce_transport_for_route(req.uri().path()) {
        let remote = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|connect_info| connect_info.0);
        match state
            .transport
            .verified_client_certificate(remote, req.headers())
        {
            Ok(Some(certificate)) => {
                req.extensions_mut().insert(certificate);
            }
            Ok(None) => {}
            Err(kind) => return transport_rejection_for_route(&state, kind, req.uri().path()),
        }
    }
    if let Err(error) = validate_uri_credentials(
        req.uri(),
        uri_credential_policy_for_request(req.method(), req.uri().path()),
    ) {
        if super::resource_authentication::protected_resource_matched_route(
            &state,
            req.method(),
            req.extensions().get::<MatchedPath>(),
        ) {
            return super::resource_authentication::resource_uri_rejection(
                error,
                state.issuer.as_str(),
                req.headers(),
            );
        }
        return query_rejection_response(
            error,
            state.issuer.as_str(),
            requires_bearer_for_matched_route(
                &state,
                req.method(),
                req.extensions().get::<MatchedPath>(),
            ),
        );
    }
    next.run(req).await
}

fn should_enforce_transport_for_route(path: &str) -> bool {
    path != "/health"
}

pub(super) fn transport_rejection_for_route(
    state: &AppState,
    kind: TransportRejectionKind,
    path: &str,
) -> Response {
    if kind == TransportRejectionKind::MtlsClientCertMissing
        && matches!(
            path,
            "/userinfo" | "/resource" | "/application/authorization" | "/oauth/upstream/refresh"
        )
    {
        return super::oauth_errors::bearer_json_error_with_iss(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            Some("client certificate does not match the token binding"),
            state.issuer.as_str(),
        );
    }
    transport_rejection(state, kind)
}

pub(super) fn transport_rejection(state: &AppState, kind: TransportRejectionKind) -> Response {
    let (status, error, description) = match kind {
        TransportRejectionKind::UntrustedProxy | TransportRejectionKind::MissingRemoteAddr => (
            StatusCode::FORBIDDEN,
            "access_denied",
            "request did not originate from a trusted proxy",
        ),
        TransportRejectionKind::MissingForwardedHeader => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "forwarded header required to assert HTTPS transport",
        ),
        TransportRejectionKind::MalformedForwardedHeader => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "forwarded header was malformed",
        ),
        TransportRejectionKind::InsecureProto => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "insecure transport: HTTPS required",
        ),
        TransportRejectionKind::MtlsClientCertMissing => (
            StatusCode::FORBIDDEN,
            "access_denied",
            "client certificate required by ingress policy",
        ),
    };

    let body = serde_json::json!({
        "error": error,
        "error_description": description,
        "iss": state.issuer.as_str(),
    });
    let mut response = (status, Json(body)).into_response();
    util::apply_no_cache_headers(&mut response);
    response
}

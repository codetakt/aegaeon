use super::request_admission::enforce_no_credentials_in_request_uri;
use super::AppState;
use crate::middleware::tls::TransportRejectionKind;
use crate::util;
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use std::net::SocketAddr;

pub(super) async fn transport_security_middleware(
    State(state): State<AppState>,
    req: axum::http::Request<Body>,
    next: Next,
) -> Response {
    if should_enforce_transport_for_route(req.uri().path()) {
        let remote = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|connect_info| connect_info.0);
        if let Err(kind) = state.transport.enforce(remote, req.headers()) {
            return transport_rejection(&state, kind);
        }
    }
    if let Err(resp) =
        enforce_no_credentials_in_request_uri(req.method(), req.uri(), state.issuer.as_str())
    {
        return resp;
    }
    next.run(req).await
}

fn should_enforce_transport_for_route(path: &str) -> bool {
    path != "/health"
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
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client certificate required for mTLS-bound tokens",
        ),
    };

    let body = serde_json::json!({
        "error": error,
        "error_description": description,
        "iss": state.issuer.as_str(),
    });
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"aegaeon\", error=\"tls_required\""),
    );
    util::apply_no_cache_headers(&mut response);
    response
}

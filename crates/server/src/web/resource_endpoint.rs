mod outcome;
mod policy;
mod sender;

pub(super) use policy::process_resource_request;

use super::oauth_errors::{authorization_header, bearer_header_error, dpop_invalid_token_response};
use super::request_admission::enforce_no_credentials_in_uri;
use super::{
    dpop_binding_from_request, transport_rejection, trusted_mtls_fingerprint, AppState,
    X_FORWARDED_CLIENT_CERT_HEADER,
};
use axum::{
    extract::{ConnectInfo, OriginalUri, State},
    http::{HeaderMap, Uri},
    response::Response,
};
use std::net::SocketAddr;

pub(super) async fn resource(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let issuer_base = state.issuer.as_str();
    if let Err(kind) = state.transport.enforce(Some(remote), &headers) {
        return transport_rejection(&state, kind);
    }
    if let Err(resp) = enforce_no_credentials_in_uri(&uri, issuer_base) {
        return resp;
    }

    let auth_header = match authorization_header(&headers) {
        Ok(header) => header.map(ToString::to_string),
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

    let start = std::time::Instant::now();
    let outcome = process_resource_request(
        state.tokens.validator.as_ref(),
        auth_header,
        binding.as_ref(),
        mtls.as_deref(),
        issuer_base,
    )
    .await;
    let latency = start.elapsed().as_secs_f64();

    crate::metrics_integration::MetricsIntegration::with_global(|metrics| {
        metrics.record_resource_access(
            outcome.mode.as_str(),
            outcome.success,
            outcome.reason.as_deref(),
        );
        metrics
            .metrics
            .request_latency
            .with_label_values(&["/resource", "GET"])
            .observe(latency);
    });

    outcome.response
}

use super::transport_boundary::transport_rejection_for_route;
use crate::middleware::dpop::DpopEndpointRole;
use crate::web::token_sender_binding::dpop_error_response;
mod outcome;
mod policy;
mod sender;
#[cfg(test)]
mod tests;

pub(super) use policy::process_resource_request;

use super::oauth_errors::{authorization_header, bearer_header_error, dpop_invalid_token_response};
use super::resource_authentication::{enforce_resource_uri, resource_invalid_request};
use super::{
    dpop_binding_from_request, trusted_mtls_fingerprint, AppState, X_FORWARDED_CLIENT_CERT_HEADER,
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
    method: http::Method,
    headers: HeaderMap,
) -> Response {
    let issuer_base = state.issuer.as_str();
    if let Err(kind) = state.transport.enforce(Some(remote), &headers) {
        return transport_rejection_for_route(&state, kind, uri.path());
    }
    if let Err(resp) = enforce_resource_uri(&uri, issuer_base, &headers) {
        return resp;
    }

    let auth_header = match authorization_header(&headers) {
        Ok(header) => header.map(ToString::to_string),
        Err(err) => return bearer_header_error(issuer_base, "Authorization", err),
    };

    let admission_start = std::time::Instant::now();
    let credentials =
        match policy::admit_resource_authorization(auth_header.as_deref(), issuer_base) {
            Ok(credentials) => credentials,
            Err(outcome) => {
                record_resource_outcome(&outcome, &method, admission_start.elapsed().as_secs_f64());
                return outcome.response;
            }
        };
    let presented_scheme = credentials.scheme;

    let path = uri
        .path_and_query()
        .map_or(uri.path(), axum::http::uri::PathAndQuery::as_str);
    let uri_for_dpop: Uri = match path.parse() {
        Ok(uri) => uri,
        Err(_) => return dpop_invalid_token_response(issuer_base, "DPoP proof validation failed"),
    };
    let binding = match dpop_binding_from_request(
        state.dpop.as_ref(),
        DpopEndpointRole::ResourceServer,
        &method,
        &uri_for_dpop,
        &headers,
    ) {
        Ok(binding) => binding,
        Err(error) => {
            return dpop_error_response(issuer_base, DpopEndpointRole::ResourceServer, error)
        }
    };

    let mtls = match trusted_mtls_fingerprint(&state, &headers) {
        Ok(mtls) => mtls,
        Err(err) => {
            return resource_invalid_request(
                issuer_base,
                presented_scheme,
                &err.description(X_FORWARDED_CLIENT_CERT_HEADER),
            )
        }
    };

    let start = std::time::Instant::now();
    let mut outcome = process_resource_request(
        state.tokens.validator.as_ref(),
        auth_header.clone(),
        binding.as_ref(),
        mtls.as_deref(),
        issuer_base,
    )
    .await;
    outcome = outcome
        .check_application(&state, auth_header.as_deref())
        .await
        .with_presentation(presented_scheme);
    let latency = start.elapsed().as_secs_f64();

    record_resource_outcome(&outcome, &method, latency);

    outcome.response
}

fn record_resource_outcome(
    outcome: &outcome::ResourceOutcome,
    method: &http::Method,
    latency: f64,
) {
    crate::metrics_integration::MetricsIntegration::with_global(|metrics| {
        metrics.record_resource_access(
            outcome.mode.as_str(),
            outcome.success,
            outcome.reason.as_deref(),
        );
        metrics
            .metrics
            .request_latency
            .with_label_values(&["/resource", method.as_str()])
            .observe(latency);
    });
}

//! Selected registration and authentication material for one request.
use axum::{http::StatusCode, response::Response};
use std::sync::Arc;

use super::AppState;

/// Replay and remote JWKS state remain shared; selected client data is copied.
pub(super) fn request_state(state: &AppState, ids: &[&str]) -> Result<AppState, Response> {
    let mut snapshot = state.clone();
    snapshot.clients = Arc::new(state.clients.try_request_snapshot(ids).map_err(|error| {
        tracing::error!(target: "oauth", error = %error, "client authentication snapshot failed");
        super::oauth_errors::no_cache_json_error_with_iss(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            Some("client authentication snapshot unavailable"),
            state.issuer.as_str(),
        )
    })?);
    Ok(snapshot)
}

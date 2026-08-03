use axum::{http::StatusCode, response::Response};

use super::super::super::error_response;

mod dcr;
mod federation;
mod mtls;
mod security;
mod session;
mod token;

pub(super) use dcr::validate_dcr_sender_methods;
pub(super) use federation::validate_upstream_and_federation_ranges;
pub(super) use mtls::validate_mtls_base_url;
pub(super) use security::validate_security_and_replay_ranges;
pub(super) use session::validate_session_and_protocol_ranges;
pub(super) use token::validate_allowlists_and_token_ttls;

pub(super) fn invalid_request(message: &str, request_id: &str) -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        message,
        None,
        Some(request_id),
    )
}

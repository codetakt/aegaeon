use super::super::oauth_errors::json_error_with_iss;
use axum::{http::StatusCode, response::Response};

pub(super) fn internal_server_error(issuer_base: &str, description: &'static str) -> Response {
    json_error_with_iss(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        Some(description),
        issuer_base,
    )
}

pub(super) fn corrupted_account_link_row_error(issuer_base: &str) -> Response {
    internal_server_error(issuer_base, "upstream account link row is corrupted")
}

pub(super) fn corrupted_upstream_client_row_error(issuer_base: &str) -> Response {
    internal_server_error(issuer_base, "upstream client row is corrupted")
}

use super::error_response;
use crate::local_credentials;
use axum::{http::StatusCode, response::Response};

pub(super) fn hash_password(password: &str) -> Result<String, Response> {
    local_credentials::hash_password(password).map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Password hashing failed",
            None,
            None,
        )
    })
}

pub(super) fn verify_password_or_dummy(password: &str, encoded_hash: Option<&str>) -> bool {
    local_credentials::verify_password_or_dummy(password, encoded_hash)
}

pub(super) fn validate_bootstrap_owner_password(password: &str) -> Result<(), &'static str> {
    if password.trim().is_empty() {
        return Err("Password must not be empty");
    }
    local_credentials::validate_password(password)
}

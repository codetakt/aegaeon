use crate::web::management::error_response;
use axum::{http::StatusCode, response::Response};

pub(in crate::web::management) fn validate_dcr_bearer_token<'a>(
    raw: &'a str,
    request_id: &str,
) -> Result<&'a str, Response> {
    let token = raw.trim();
    if token.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "token must not be empty",
            None,
            Some(request_id),
        ));
    }
    if token.len() < crate::dcr_persistence::MIN_DCR_BEARER_TOKEN_BYTES {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "token must contain at least 32 bytes of secret material",
            None,
            Some(request_id),
        ));
    }
    Ok(token)
}

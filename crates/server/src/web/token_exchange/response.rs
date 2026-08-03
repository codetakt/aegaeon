use axum::{http::StatusCode, response::Response};
use serde_json::json;

use super::super::{token_json_response, OAUTH_TOKEN_TYPE_ACCESS_TOKEN};

pub(super) fn token_exchange_success_response(
    token: &str,
    expires_in: u64,
    scope: Option<String>,
    authorization_details: Option<serde_json::Value>,
) -> Response {
    let mut body = json!({
        "access_token": token,
        "issued_token_type": OAUTH_TOKEN_TYPE_ACCESS_TOKEN,
        "token_type": "Bearer",
        "expires_in": expires_in,
    });
    if let Some(scope) = scope {
        body["scope"] = json!(scope);
    }
    if let Some(authorization_details) = authorization_details {
        body["authorization_details"] = authorization_details;
    }
    token_json_response(StatusCode::OK, body)
}

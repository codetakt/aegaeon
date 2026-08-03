use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use std::fmt::Display;

use crate::util;

pub(super) fn token_json_response(status: StatusCode, body: Value) -> Response {
    let mut response = (status, Json(body)).into_response();
    util::apply_no_cache_headers(&mut response);
    response
}

pub(super) fn token_error_response(
    status: StatusCode,
    error: &str,
    error_description: Option<&str>,
) -> Response {
    let mut body = json!({ "error": error });
    if let Some(error_description) = error_description {
        body["error_description"] = json!(error_description);
    }
    token_json_response(status, body)
}

pub(super) fn token_internal_error_response(
    context: &'static str,
    description: Option<&str>,
) -> Response {
    if let Some(description) = description {
        tracing::error!(target: "oauth", error = %description, context, "token endpoint failed internally");
    } else {
        tracing::error!(target: "oauth", context, "token endpoint failed internally");
    }
    token_error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        Some("token endpoint failed internally"),
    )
}

pub(super) fn token_registry_state_error_response(
    operation: &'static str,
    error: impl Display,
) -> Response {
    let description = error.to_string();
    token_internal_error_response(operation, Some(&description))
}

pub(super) fn token_success_body(
    access_token: &str,
    token_type: &str,
    expires_in: u64,
    refresh_token: Option<String>,
    scope: Option<String>,
    id_token: Option<String>,
    authorization_details: Option<Value>,
) -> Value {
    let mut body = json!({
        "access_token": access_token,
        "token_type": token_type,
        "expires_in": expires_in,
    });
    if let Some(refresh_token) = refresh_token {
        body["refresh_token"] = json!(refresh_token);
    }
    if let Some(scope) = scope {
        body["scope"] = json!(scope);
    }
    if let Some(id_token) = id_token {
        body["id_token"] = json!(id_token);
    }
    if let Some(authorization_details) = authorization_details {
        body["authorization_details"] = authorization_details;
    }
    body
}

pub(super) fn token_issuer_error_response(
    error: &str,
    error_description: Option<&str>,
) -> Response {
    if error == "server_error" {
        return token_internal_error_response("token_issuer", error_description);
    }
    let mut body = json!({ "error": error });
    if let Some(error_description) = error_description {
        body["error_description"] = json!(error_description);
    }
    token_json_response(StatusCode::BAD_REQUEST, body)
}

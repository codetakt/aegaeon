use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::util;

use super::super::super::oauth_errors::json_error_with_iss;

#[derive(Debug)]
pub(in crate::web) struct RequestObjectResolutionError {
    pub(in crate::web) status: StatusCode,
    pub(in crate::web) error: &'static str,
    pub(in crate::web) error_description: String,
}

impl RequestObjectResolutionError {
    pub(super) fn invalid_request(description: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_request",
            error_description: description.into(),
        }
    }

    pub(super) fn invalid_authorization_details(description: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_authorization_details",
            error_description: description.into(),
        }
    }

    pub(super) fn invalid_target(description: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_target",
            error_description: description.into(),
        }
    }

    pub(super) fn internal_error(description: impl Into<String>) -> Self {
        let description = description.into();
        tracing::error!(
            target: "oauth",
            error = %description,
            "request object resolution failed internally"
        );
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: "internal_error",
            error_description: "request object processing failed internally".to_string(),
        }
    }
}

pub(in crate::web) fn request_object_resolution_error_response(
    issuer_base: &str,
    err: &RequestObjectResolutionError,
) -> Response {
    let mut response = json_error_with_iss(
        err.status,
        err.error,
        Some(&err.error_description),
        issuer_base,
    );
    util::apply_no_cache_headers(&mut response);
    response
}

pub(in crate::web) fn request_object_resolution_error_json_response(
    err: &RequestObjectResolutionError,
) -> Response {
    let mut response = (
        err.status,
        Json(json!({
            "error": err.error,
            "error_description": err.error_description,
        })),
    )
        .into_response();
    util::apply_no_cache_headers(&mut response);
    response
}

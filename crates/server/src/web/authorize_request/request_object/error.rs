use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::util;

use super::super::super::oauth_errors::json_error_with_iss;

#[derive(Debug)]
pub(in crate::web) struct RequestObjectResolutionError {
    pub(in crate::web) status: StatusCode,
    pub(in crate::web) error: &'static str,
    pub(in crate::web) error_description: String,
}

impl RequestObjectResolutionError {
    pub(super) fn invalid_request_object(description: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_request_object",
            error_description: description.into(),
        }
    }

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
        Json(crate::oauth_error::json_body(
            err.error,
            Some(&err.error_description),
        )),
    )
        .into_response();
    util::apply_no_cache_headers(&mut response);
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn oauth_error_encoding_request_object_direct_json_keeps_status(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let error = RequestObjectResolutionError {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_target",
            error_description: "bad\"\\é".into(),
        };
        let response = request_object_resolution_error_json_response(&error);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers()[axum::http::header::CACHE_CONTROL],
            "no-store"
        );
        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 65536).await?)?;
        assert_eq!(body["error"], "invalid_target");
        assert_eq!(body["error_description"], "bad???");
        assert_eq!(error.error_description, "bad\"\\é");
        Ok(())
    }
}

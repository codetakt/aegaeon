use super::error_response;
use crate::federation::FederationError;
use axum::{http::StatusCode, response::Response};

pub(super) fn federation_management_error_response(
    error: FederationError,
    request_id: &str,
) -> Response {
    match error {
        FederationError::Fetch(message) => error_response(
            StatusCode::BAD_GATEWAY,
            "upstream_unavailable",
            "Failed to fetch federation metadata",
            Some(serde_json::Value::String(message)),
            Some(request_id),
        ),
        FederationError::Storage(message) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Failed to access federation state",
            Some(serde_json::Value::String(message)),
            Some(request_id),
        ),
        FederationError::ChainResolution(message) => error_response(
            StatusCode::CONFLICT,
            "trust_chain_resolution_failed",
            "Failed to resolve federation trust chain",
            Some(serde_json::Value::String(message)),
            Some(request_id),
        ),
        FederationError::Internal(message) => {
            tracing::error!(
                target: "management",
                request_id,
                error = %message,
                "federation management operation failed internally"
            );
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Federation operation failed internally",
                None,
                Some(request_id),
            )
        }
        FederationError::Validation(message) => error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid federation management request",
            Some(serde_json::Value::String(message)),
            Some(request_id),
        ),
        other => {
            let detail = other.to_string();
            error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Federation operation failed",
                Some(serde_json::Value::String(detail)),
                Some(request_id),
            )
        }
    }
}

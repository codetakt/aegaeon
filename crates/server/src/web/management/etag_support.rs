use axum::{
    http::{header::ETAG, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use super::{error_response, sha256_hex};

pub(super) fn representation_etag<T: Serialize>(value: &T) -> Result<HeaderValue, Response> {
    let bytes = serde_json::to_vec(value).map_err(|_| {
        super::management_internal_error("unknown", "Failed to serialize resource representation")
    })?;
    HeaderValue::from_str(&format!("\"{}\"", sha256_hex(&bytes))).map_err(|_| {
        super::management_internal_error("unknown", "Failed to construct resource ETag")
    })
}

pub(super) fn etagged_json<T: Serialize>(value: T, request_id: &str) -> Response {
    let etag = match representation_etag(&value) {
        Ok(etag) => etag,
        Err(_) => {
            return super::management_internal_error(
                request_id,
                "Failed to construct resource ETag",
            )
        }
    };
    (StatusCode::OK, [(ETAG, etag)], Json(value)).into_response()
}

pub(super) fn enforce_if_match<T: Serialize>(
    headers: &HeaderMap,
    current: &T,
    request_id: &str,
) -> Result<(), Response> {
    let Some(if_match) = headers.get(axum::http::header::IF_MATCH) else {
        return Ok(());
    };
    let current = representation_etag(current).map_err(|_| {
        super::management_internal_error(request_id, "Failed to construct resource ETag")
    })?;
    let matches = if_match
        .to_str()
        .ok()
        .map(|value| {
            value.trim() == "*"
                || value
                    .split(',')
                    .map(str::trim)
                    .any(|candidate| candidate.as_bytes() == current.as_bytes())
        })
        .unwrap_or(false);
    if matches {
        Ok(())
    } else {
        Err(error_response(
            StatusCode::PRECONDITION_FAILED,
            "precondition_failed",
            "The resource has changed since it was retrieved",
            None,
            Some(request_id),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_optional_if_match_contract(current: serde_json::Value) {
        let mut headers = HeaderMap::new();
        assert!(enforce_if_match(&headers, &current, "req").is_ok());
        headers.insert(
            axum::http::header::IF_MATCH,
            representation_etag(&current).expect("etag"),
        );
        assert!(enforce_if_match(&headers, &current, "req").is_ok());
        headers.insert(
            axum::http::header::IF_MATCH,
            HeaderValue::from_static("\"stale\""),
        );
        let response = enforce_if_match(&headers, &current, "req").expect_err("stale ETag");
        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    }

    #[test]
    fn client_if_match_supports_matching_stale_and_omitted_headers() {
        assert_optional_if_match_contract(serde_json::json!({"kind": "client", "id": "client-1"}));
    }

    #[test]
    fn policies_if_match_supports_matching_stale_and_omitted_headers() {
        assert_optional_if_match_contract(serde_json::json!({"kind": "policies", "version": 2}));
    }
}

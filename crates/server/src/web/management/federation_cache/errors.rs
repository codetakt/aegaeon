use super::super::error_response;
use axum::response::Response;
use http::StatusCode;

pub(super) fn federation_entity_cache_not_found(request_id: &str) -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "Federation entity cache entry not found",
        None,
        Some(request_id),
    )
}

pub(super) fn federation_trust_chain_not_found(request_id: &str) -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "Federation trust chain not found",
        None,
        Some(request_id),
    )
}

pub(in crate::web::management) fn federation_trust_anchor_not_found(request_id: &str) -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "Trust anchor not found",
        None,
        Some(request_id),
    )
}

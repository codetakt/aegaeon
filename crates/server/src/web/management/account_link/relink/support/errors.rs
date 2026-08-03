use super::super::super::super::{error_response, management_internal_error};
use axum::{http::StatusCode, response::Response};

pub(in crate::web::management::account_link::relink) fn account_link_not_found(
    request_id: &str,
) -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "Account link not found",
        None,
        Some(request_id),
    )
}

pub(super) fn account_links_not_found(request_id: &str) -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "One or more account links were not found",
        None,
        Some(request_id),
    )
}

pub(super) fn account_links_reorder_failed(request_id: &str) -> Response {
    management_internal_error(request_id, "Failed to reorder account links")
}

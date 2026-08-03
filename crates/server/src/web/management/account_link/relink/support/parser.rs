use super::super::super::super::error_response;
use axum::{http::StatusCode, response::Response};
use std::collections::HashSet;
use uuid::Uuid;

pub(in crate::web::management::account_link::relink) fn parse_target_end_user_id(
    value: &str,
    request_id: &str,
) -> Result<Uuid, Response> {
    Uuid::parse_str(value).map_err(|_| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid endUserId",
            None,
            Some(request_id),
        )
    })
}

pub(in crate::web::management::account_link::relink) fn parse_account_link_id_list(
    raw_account_link_ids: &[String],
    request_id: &str,
) -> Result<(Vec<String>, Vec<Uuid>), Response> {
    if raw_account_link_ids.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "At least one accountLinkId is required",
            None,
            Some(request_id),
        ));
    }

    let mut seen_account_link_ids = HashSet::new();
    let mut requested_account_link_ids = Vec::new();
    let mut account_link_ids = Vec::new();
    for raw_account_link_id in raw_account_link_ids {
        let account_link_id = Uuid::parse_str(raw_account_link_id).map_err(|_| {
            error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid accountLinkId",
                None,
                Some(request_id),
            )
        })?;
        if seen_account_link_ids.insert(account_link_id) {
            requested_account_link_ids.push(account_link_id.to_string());
            account_link_ids.push(account_link_id);
        }
    }

    Ok((requested_account_link_ids, account_link_ids))
}

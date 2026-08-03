use axum::{http::StatusCode, response::Response};
use uuid::Uuid;

use crate::management::types::AccountLinkSummary;
use crate::web::management::error_response;

pub(in crate::web::management::account_link_conflict) fn ensure_account_link_conflict_connection_matches(
    existing_account_link: &AccountLinkSummary,
    connection_id: Uuid,
    request_id: &str,
) -> Result<(), Response> {
    if existing_account_link.connection_id != connection_id.to_string() {
        return Err(error_response(
            StatusCode::CONFLICT,
            "conflict",
            "Account link conflict belongs to a different connection",
            None,
            Some(request_id),
        ));
    }

    Ok(())
}

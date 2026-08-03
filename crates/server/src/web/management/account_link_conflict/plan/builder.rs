use axum::{http::StatusCode, response::Response};
use uuid::Uuid;

use crate::management::types::{
    AccountLinkConflictCandidate, AccountLinkSummary, ResolveAccountLinkConflictRequest, User,
};
use crate::web::management::{
    account_link_candidate_is_low_confidence, error_response, management_internal_error,
    resolve_account_link_inactive_target_handling, resolve_account_link_low_confidence_handling,
    resolve_account_link_refresh_token_action,
};

use super::model::AccountLinkConflictResolutionPlan;

pub(in crate::web::management::account_link_conflict) fn build_account_link_conflict_resolution_plan(
    existing_account_link: &AccountLinkSummary,
    target_user: &User,
    selected_candidate: Option<AccountLinkConflictCandidate>,
    req: &ResolveAccountLinkConflictRequest,
    request_id: &str,
) -> Result<AccountLinkConflictResolutionPlan, Response> {
    let existing_account_link_id = Uuid::parse_str(&existing_account_link.id)
        .map_err(|_| management_internal_error(request_id, "Invalid account link id"))?;
    let moving_to_different_user = existing_account_link.end_user_id != target_user.id;
    let selected_candidate_ref = selected_candidate.as_ref();
    let refresh_token_action = if moving_to_different_user {
        resolve_account_link_refresh_token_action(
            usize::from(existing_account_link.has_refresh_token),
            req.upstream_refresh_token_handling,
        )
        .map_err(|message| conflict_response(message, request_id))?
    } else {
        None
    };
    let low_confidence_action = if moving_to_different_user {
        resolve_account_link_low_confidence_handling(
            account_link_candidate_is_low_confidence(selected_candidate_ref),
            req.low_confidence_handling,
        )
        .map_err(|message| conflict_response(message, request_id))?
    } else {
        None
    };
    let inactive_target_action = if moving_to_different_user {
        resolve_account_link_inactive_target_handling(
            target_user.status != "ACTIVE",
            req.inactive_target_handling,
        )
        .map_err(|message| conflict_response(message, request_id))?
    } else {
        None
    };

    Ok(AccountLinkConflictResolutionPlan {
        existing_account_link_id,
        moving_to_different_user,
        selected_candidate,
        refresh_token_action,
        low_confidence_action,
        inactive_target_action,
    })
}

fn conflict_response(message: &'static str, request_id: &str) -> Response {
    error_response(
        StatusCode::CONFLICT,
        "conflict",
        message,
        None,
        Some(request_id),
    )
}

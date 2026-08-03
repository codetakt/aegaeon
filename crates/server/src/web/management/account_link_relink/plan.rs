use crate::management::types::*;
use crate::web::management::{
    error_response, management_internal_error, resolve_account_link_inactive_target_handling,
    resolve_account_link_refresh_token_action, AccountLinkRefreshTokenAction,
};
use axum::{http::StatusCode, response::Response};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub(in crate::web::management) struct BulkAccountLinkRelinkPlan {
    pub(in crate::web::management) moving_account_link_ids: Vec<Uuid>,
    pub(in crate::web::management) moving_requested_account_link_ids: Vec<String>,
    pub(in crate::web::management) moving_refresh_token_count: usize,
    pub(in crate::web::management) refresh_token_action: Option<AccountLinkRefreshTokenAction>,
    pub(in crate::web::management) inactive_target_action:
        Option<AccountLinkInactiveTargetHandling>,
}

pub(in crate::web::management) type AccountLinkRelinkDecision = (
    Option<AccountLinkRefreshTokenAction>,
    Option<AccountLinkInactiveTargetHandling>,
);

pub(in crate::web::management) fn build_bulk_account_link_relink_plan(
    existing_account_links: &[AccountLinkSummary],
    target_user: &User,
    req: &BulkRelinkAccountLinksRequest,
    request_id: &str,
) -> Result<BulkAccountLinkRelinkPlan, Response> {
    let has_moving_account_links = existing_account_links
        .iter()
        .any(|account_link| account_link.end_user_id != target_user.id);
    let inactive_target_action = if has_moving_account_links {
        resolve_account_link_inactive_target_handling(
            target_user.status != "ACTIVE",
            req.inactive_target_handling,
        )
        .map_err(|message| conflict_response(message, request_id))?
    } else {
        None
    };

    let mut moving_account_link_ids = Vec::new();
    let mut moving_requested_account_link_ids = Vec::new();
    let mut moving_refresh_token_count = 0usize;
    for account_link in existing_account_links {
        if account_link.end_user_id == target_user.id {
            continue;
        }

        let account_link_id = Uuid::parse_str(&account_link.id)
            .map_err(|_| management_internal_error(request_id, "Invalid account link id"))?;
        moving_requested_account_link_ids.push(account_link.id.clone());
        moving_account_link_ids.push(account_link_id);
        if account_link.has_refresh_token {
            moving_refresh_token_count += 1;
        }
    }

    let refresh_token_action = resolve_account_link_refresh_token_action(
        moving_refresh_token_count,
        req.upstream_refresh_token_handling,
    )
    .map_err(|message| conflict_response(message, request_id))?;

    Ok(BulkAccountLinkRelinkPlan {
        moving_account_link_ids,
        moving_requested_account_link_ids,
        moving_refresh_token_count,
        refresh_token_action,
        inactive_target_action,
    })
}

pub(in crate::web::management) fn build_relink_account_link_plan(
    existing_account_link: &AccountLinkSummary,
    target_user: &User,
    req: &RelinkAccountLinkRequest,
    request_id: &str,
) -> Result<Option<AccountLinkRelinkDecision>, Response> {
    if existing_account_link.end_user_id == target_user.id {
        return Ok(None);
    }

    let inactive_target_action = resolve_account_link_inactive_target_handling(
        target_user.status != "ACTIVE",
        req.inactive_target_handling,
    )
    .map_err(|message| conflict_response(message, request_id))?;
    let refresh_token_action = resolve_account_link_refresh_token_action(
        usize::from(existing_account_link.has_refresh_token),
        req.upstream_refresh_token_handling,
    )
    .map_err(|message| conflict_response(message, request_id))?;

    Ok(Some((refresh_token_action, inactive_target_action)))
}

fn conflict_response(message: &str, request_id: &str) -> Response {
    error_response(
        StatusCode::CONFLICT,
        "conflict",
        message,
        None,
        Some(request_id),
    )
}

use axum::response::Response;
use sqlx::PgPool;

use crate::management::types::{AccountLinkSummary, RelinkAccountLinkRequest};
use crate::web::management::state::ManagementSession;

use super::super::super::super::account_link_relink::{
    build_relink_account_link_plan, relink_account_link_audit_event, relink_account_links_rows,
    AccountLinkRelinkRowUpdateMessages,
};
use super::super::super::super::{
    begin_management_transaction, commit_management_transaction,
    ensure_account_link_target_not_deleted, load_account_link_summary_by_id_for_update,
    load_account_link_summary_by_id_required, load_account_link_target_user_for_update,
    require_account_link_lifecycle_scope, require_team_lifecycle_role_in_transaction,
    write_account_link_audit_event,
};
use super::super::support::{account_link_not_found, parse_target_end_user_id};

pub(in crate::web::management::account_link::relink::single) async fn relink_account_link_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentAccountLinkPath,
    req: &RelinkAccountLinkRequest,
    session: &ManagementSession,
    request_id: &str,
) -> Result<AccountLinkSummary, Response> {
    let scope = require_account_link_lifecycle_scope(pool, params, session, request_id).await?;
    let account_link_id = params.account_link_id(request_id)?;
    let target_end_user_id = parse_target_end_user_id(&req.end_user_id, request_id)?;
    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        scope.team,
        session,
        request_id,
        "Insufficient permissions for account link operations",
    )
    .await?;
    let target_user =
        load_account_link_target_user_for_update(&mut tx, scope, target_end_user_id, request_id)
            .await?;
    ensure_account_link_target_not_deleted(
        &target_user,
        request_id,
        "Cannot relink to a deleted user",
    )?;
    let existing_account_link =
        load_account_link_summary_by_id_for_update(&mut tx, scope, account_link_id, request_id)
            .await?
            .ok_or_else(|| account_link_not_found(request_id))?;

    let Some((refresh_token_action, inactive_target_action)) =
        build_relink_account_link_plan(&existing_account_link, &target_user, req, request_id)?
    else {
        commit_management_transaction(tx, request_id).await?;
        return Ok(existing_account_link);
    };

    relink_account_links_rows(
        &mut tx,
        scope.environment,
        target_end_user_id,
        &[account_link_id],
        refresh_token_action,
        request_id,
        AccountLinkRelinkRowUpdateMessages {
            not_found: "Account link not found",
            failure: "Failed to relink account link",
        },
    )
    .await?;
    let updated_account_link =
        load_account_link_summary_by_id_required(&mut *tx, scope, account_link_id, request_id)
            .await?;
    write_account_link_audit_event(
        &mut tx,
        scope,
        session.administrator_id,
        request_id,
        relink_account_link_audit_event(
            &existing_account_link,
            &updated_account_link,
            &target_user,
            account_link_id,
            refresh_token_action,
            inactive_target_action,
        ),
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;

    Ok(updated_account_link)
}

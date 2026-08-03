use super::super::super::super::account_link_relink::{
    build_bulk_account_link_relink_plan, bulk_account_link_relinked_audit_event,
    relink_account_links_rows, AccountLinkRelinkRowUpdateMessages,
};
use super::super::super::super::{
    begin_management_transaction, commit_management_transaction,
    ensure_account_link_target_not_deleted, load_account_link_target_user_for_update,
    require_account_link_lifecycle_scope, require_team_lifecycle_role_in_transaction,
    write_account_link_audit_event,
};
use super::super::support::{
    load_account_link_summaries_by_ids, load_account_link_summaries_by_ids_for_update,
    parse_account_link_id_list, parse_target_end_user_id, reorder_account_links,
};
use crate::management::types::{BulkRelinkAccountLinksRequest, BulkRelinkAccountLinksResponse};
use crate::web::management::state::ManagementSession;
use axum::response::Response;
use sqlx::PgPool;

pub(super) async fn bulk_relink_account_links_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentPath,
    req: &BulkRelinkAccountLinksRequest,
    session: &ManagementSession,
    request_id: &str,
) -> Result<BulkRelinkAccountLinksResponse, Response> {
    let scope = require_account_link_lifecycle_scope(pool, params, session, request_id).await?;
    let (requested_account_link_ids, account_link_ids) =
        parse_account_link_id_list(&req.account_link_ids, request_id)?;
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
    let existing_account_links = load_account_link_summaries_by_ids_for_update(
        &mut tx,
        scope,
        &account_link_ids,
        request_id,
    )
    .await?;
    let plan = build_bulk_account_link_relink_plan(
        &existing_account_links,
        &target_user,
        req,
        request_id,
    )?;

    if plan.moving_account_link_ids.is_empty() {
        commit_management_transaction(tx, request_id).await?;
        return Ok(BulkRelinkAccountLinksResponse {
            account_links: reorder_account_links(
                &requested_account_link_ids,
                existing_account_links,
                request_id,
            )?,
        });
    }

    relink_account_links_rows(
        &mut tx,
        scope.environment,
        target_end_user_id,
        &plan.moving_account_link_ids,
        plan.refresh_token_action,
        request_id,
        AccountLinkRelinkRowUpdateMessages {
            not_found: "One or more account links were not found",
            failure: "Failed to relink account links",
        },
    )
    .await?;
    let updated_account_links =
        load_account_link_summaries_by_ids(&mut *tx, scope, &account_link_ids, request_id).await?;
    let ordered_account_links = reorder_account_links(
        &requested_account_link_ids,
        updated_account_links,
        request_id,
    )?;
    write_account_link_audit_event(
        &mut tx,
        scope,
        session.administrator_id,
        request_id,
        bulk_account_link_relinked_audit_event(
            &target_user,
            &ordered_account_links,
            &existing_account_links,
            &requested_account_link_ids,
            &plan,
        ),
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;

    Ok(BulkRelinkAccountLinksResponse {
        account_links: ordered_account_links,
    })
}

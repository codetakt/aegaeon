use super::super::super::{
    begin_management_transaction, commit_management_transaction,
    ensure_account_link_target_not_deleted, load_account_link_connection_for_update,
    load_account_link_target_user_for_update, parse_account_link_subject, parse_uuid_param,
    require_account_link_lifecycle_scope, require_team_lifecycle_role_in_transaction,
    write_account_link_audit_event,
};
use super::super::audit::account_link_conflict_resolved_audit_event;
use super::super::plan::{
    build_account_link_conflict_resolution_plan, ensure_account_link_conflict_connection_matches,
    load_selected_account_link_candidate,
};
use super::super::store::{
    apply_account_link_conflict_resolution, load_account_link_conflict_required,
};
use crate::management::types::{AccountLinkSummary, ResolveAccountLinkConflictRequest};
use crate::upstream::upstream_subject_link_hash;
use crate::web::management::state::ManagementSession;
use axum::response::Response;
use sqlx::PgPool;

pub(super) async fn resolve_account_link_conflict_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentPath,
    req: &ResolveAccountLinkConflictRequest,
    session: &ManagementSession,
    request_id: &str,
) -> Result<AccountLinkSummary, Response> {
    let scope = require_account_link_lifecycle_scope(pool, params, session, request_id).await?;
    let connection_id = parse_uuid_param(&req.connection_id, "connectionId", request_id)?;
    let target_end_user_id = parse_uuid_param(&req.end_user_id, "endUserId", request_id)?;
    let upstream_subject = parse_account_link_subject(&req.upstream_subject, request_id)?;
    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        scope.team,
        session,
        request_id,
        "Insufficient permissions for account link operations",
    )
    .await?;
    let connection =
        load_account_link_connection_for_update(&mut tx, scope, connection_id, request_id).await?;
    let target_user =
        load_account_link_target_user_for_update(&mut tx, scope, target_end_user_id, request_id)
            .await?;
    ensure_account_link_target_not_deleted(
        &target_user,
        request_id,
        "Cannot resolve a conflict to a deleted user",
    )?;

    let upstream_sub_hash = upstream_subject_link_hash(&connection.issuer_url, &upstream_subject);
    let existing_account_link = load_account_link_conflict_required(
        &mut tx,
        scope,
        &connection.issuer_url,
        &upstream_sub_hash,
        request_id,
    )
    .await?;
    ensure_account_link_conflict_connection_matches(
        &existing_account_link,
        connection_id,
        request_id,
    )?;

    let moving_to_different_user = existing_account_link.end_user_id != target_user.id;
    let selected_candidate = load_selected_account_link_candidate(
        &mut *tx,
        scope,
        &upstream_subject,
        &target_user.id,
        moving_to_different_user,
        request_id,
    )
    .await?;
    let plan = build_account_link_conflict_resolution_plan(
        &existing_account_link,
        &target_user,
        selected_candidate,
        req,
        request_id,
    )?;
    let resolved_account_link = apply_account_link_conflict_resolution(
        &mut tx,
        scope,
        target_end_user_id,
        &existing_account_link,
        &plan,
        request_id,
    )
    .await?;
    write_account_link_audit_event(
        &mut tx,
        scope,
        session.administrator_id,
        request_id,
        account_link_conflict_resolved_audit_event(
            &connection,
            &upstream_sub_hash,
            &existing_account_link,
            &resolved_account_link,
            &target_user,
            &plan,
        ),
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;

    Ok(resolved_account_link)
}

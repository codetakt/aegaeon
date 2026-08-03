use super::super::super::super::{
    account_link_exists_by_upstream_subject, begin_management_transaction,
    commit_management_transaction, ensure_account_link_target_not_deleted, error_response,
    insert_account_link_id, load_account_link_connection_for_update,
    load_account_link_summary_by_id_required, load_account_link_target_user_for_update,
    parse_account_link_subject, parse_uuid_param, require_account_link_lifecycle_scope,
    require_team_lifecycle_role_in_transaction, write_account_link_audit_event,
    AccountLinkAuditEvent,
};
use crate::management::types::{AccountLinkSummary, CreateAccountLinkRequest};
use crate::upstream::upstream_subject_link_hash;
use crate::web::management::state::ManagementSession;
use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;

pub(super) async fn create_account_link_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentPath,
    req: &CreateAccountLinkRequest,
    session: &ManagementSession,
    request_id: &str,
) -> Result<AccountLinkSummary, Response> {
    let scope = require_account_link_lifecycle_scope(pool, params, session, request_id).await?;
    let connection_id = parse_uuid_param(&req.connection_id, "connectionId", request_id)?;
    let end_user_id = parse_uuid_param(&req.end_user_id, "endUserId", request_id)?;
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
        load_account_link_target_user_for_update(&mut tx, scope, end_user_id, request_id).await?;
    ensure_account_link_target_not_deleted(&target_user, request_id, "Cannot link a deleted user")?;

    let upstream_sub_hash = upstream_subject_link_hash(&connection.issuer_url, &upstream_subject);
    if account_link_exists_by_upstream_subject(
        &mut *tx,
        scope.environment,
        &connection.issuer_url,
        &upstream_sub_hash,
        request_id,
    )
    .await?
    {
        return Err(error_response(
            StatusCode::CONFLICT,
            "conflict",
            "Account link already exists for this upstream account",
            None,
            Some(request_id),
        ));
    }

    let inserted_account_link_id = insert_account_link_id(
        &mut tx,
        scope,
        connection_id,
        &connection.issuer_url,
        &upstream_sub_hash,
        end_user_id,
        request_id,
    )
    .await?;
    let created_account_link = load_account_link_summary_by_id_required(
        &mut *tx,
        scope,
        inserted_account_link_id,
        request_id,
    )
    .await?;
    write_account_link_audit_event(
        &mut tx,
        scope,
        session.administrator_id,
        request_id,
        AccountLinkAuditEvent {
            event_type: "management.accountLink.created.v1",
            severity: "INFO",
            target_id: &created_account_link.id,
            data: serde_json::json!({
                "accountLinkId": inserted_account_link_id.to_string(),
                "connectionId": &created_account_link.connection_id,
                "connectionIdentifier": &connection.connection_identifier,
                "connectionName": &connection.name,
                "upstreamIssuer": &created_account_link.upstream_issuer,
                "endUserId": &created_account_link.end_user_id,
                "endUserSubject": &created_account_link.end_user_subject,
                "endUserEmail": &created_account_link.end_user_email,
                "hasRefreshToken": created_account_link.has_refresh_token,
            }),
        },
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;

    Ok(created_account_link)
}

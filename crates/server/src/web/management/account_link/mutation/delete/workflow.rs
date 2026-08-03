use super::super::super::super::{
    begin_management_transaction, commit_management_transaction, delete_account_link_row,
    error_response, load_account_link_summary_by_id_for_update,
    require_account_link_lifecycle_scope, require_team_lifecycle_role_in_transaction,
    write_account_link_audit_event, AccountLinkAuditEvent,
};
use crate::web::management::state::ManagementSession;
use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;

pub(super) async fn delete_account_link_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentAccountLinkPath,
    session: &ManagementSession,
    request_id: &str,
) -> Result<(), Response> {
    let scope = require_account_link_lifecycle_scope(pool, params, session, request_id).await?;
    let account_link_id = params.account_link_id(request_id)?;
    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        scope.team,
        session,
        request_id,
        "Insufficient permissions for account link operations",
    )
    .await?;
    let Some(existing_account_link) =
        load_account_link_summary_by_id_for_update(&mut tx, scope, account_link_id, request_id)
            .await?
    else {
        return Err(account_link_not_found(request_id));
    };

    if !delete_account_link_row(&mut tx, scope, account_link_id, request_id).await? {
        return Err(account_link_not_found(request_id));
    }

    write_account_link_audit_event(
        &mut tx,
        scope,
        session.administrator_id,
        request_id,
        AccountLinkAuditEvent {
            event_type: "management.accountLink.deleted.v1",
            severity: "INFO",
            target_id: &existing_account_link.id,
            data: serde_json::json!({
                "accountLinkId": account_link_id.to_string(),
                "connectionId": &existing_account_link.connection_id,
                "connectionIdentifier": &existing_account_link.connection_identifier,
                "connectionName": &existing_account_link.connection_name,
                "upstreamIssuer": &existing_account_link.upstream_issuer,
                "endUserId": &existing_account_link.end_user_id,
                "endUserSubject": &existing_account_link.end_user_subject,
                "endUserEmail": &existing_account_link.end_user_email,
                "hasRefreshToken": existing_account_link.has_refresh_token,
                "createdAt": &existing_account_link.created_at,
                "lastUsedAt": &existing_account_link.last_used_at,
            }),
        },
    )
    .await?;

    commit_management_transaction(tx, request_id).await
}

fn account_link_not_found(request_id: &str) -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "Account link not found",
        None,
        Some(request_id),
    )
}

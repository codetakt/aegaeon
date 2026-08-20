use super::super::super::super::user_inventory_support::{
    find_user_refresh_token_raw, user_runtime_store_error_response,
};
use super::super::super::super::{
    begin_management_transaction, commit_management_transaction, error_response,
    insert_user_management_runtime_command, load_managed_user_identity,
    mark_user_management_runtime_command_executing, write_user_management_audit_event_with_outcome,
    write_user_management_runtime_command_outcome, AppState, EndUserAuditEvent,
    EndUserRuntimeCommandOutcome, EndUserRuntimeCommandStatus, UserManagementContext,
};
use axum::{http::StatusCode, response::Response};
use uuid::Uuid;

#[expect(
    clippy::too_many_lines,
    reason = "existing transactional workflow; new oversized functions remain gated"
)]
pub(in crate::web::management::user_inventory::refresh_tokens) async fn revoke_user_refresh_token_inventory_inner(
    state: &AppState,
    context: &UserManagementContext,
    user_id: Uuid,
    refresh_token_id: &str,
    request_id: &str,
) -> Result<(), Response> {
    let identity = load_managed_user_identity(
        &context.pool,
        context.team_id,
        context.environment_id,
        user_id,
        request_id,
    )
    .await?;
    let raw_refresh_token =
        find_user_refresh_token_raw(state, &identity.subject, refresh_token_id, request_id)
            .await?
            .ok_or_else(|| refresh_token_not_found(request_id))?;
    let command_payload = serde_json::json!({
        "userId": user_id.to_string(),
        "refreshTokenId": refresh_token_id,
    });
    let mut tx = begin_management_transaction(&context.pool, request_id).await?;
    context
        .require_lifecycle_role_in_transaction(&mut tx, request_id)
        .await?;
    let command_id = insert_user_management_runtime_command(
        &mut tx,
        context,
        request_id,
        "management.user.refresh_token.revoke",
        user_id,
        command_payload.clone(),
    )
    .await?;
    write_user_management_audit_event_with_outcome(
        &mut tx,
        context,
        request_id,
        "AUTHORIZED",
        "INFO",
        EndUserAuditEvent {
            event_type: "management.user.refreshTokenInventory.revocationRequested.v1",
            target_id: user_id,
            data: command_payload,
        },
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;
    mark_user_management_runtime_command_executing(context, request_id, command_id, "tokenStore")
        .await?;

    let revoked_result = state
        .tokens
        .store
        .try_revoke_refresh_token_for_subject_async(identity.subject.clone(), raw_refresh_token)
        .await;
    let revoked = match revoked_result {
        Ok(revoked) => revoked,
        Err(err) => {
            write_user_management_runtime_command_outcome(
                context,
                request_id,
                EndUserRuntimeCommandOutcome {
                    command_id,
                    status: EndUserRuntimeCommandStatus::FailedUnconfirmed,
                    phase: "tokenStore",
                    result: serde_json::json!({
                        "reason": "runtimeStoreUnavailable",
                    }),
                    audit_outcome: "FAILURE",
                    audit_severity: "ERROR",
                    audit_event: EndUserAuditEvent {
                        event_type: "management.user.refreshTokenInventory.revocationFailed.v1",
                        target_id: user_id,
                        data: serde_json::json!({
                            "userId": user_id.to_string(),
                            "refreshTokenId": refresh_token_id,
                            "reason": "runtimeStoreUnavailable",
                        }),
                    },
                },
            )
            .await?;
            return Err(user_runtime_store_error_response(
                "token store",
                &err,
                "Refresh token revocation store unavailable",
                request_id,
            ));
        }
    };
    if !revoked {
        write_user_management_runtime_command_outcome(
            context,
            request_id,
            EndUserRuntimeCommandOutcome {
                command_id,
                status: EndUserRuntimeCommandStatus::FailedTerminal,
                phase: "tokenStore",
                result: serde_json::json!({
                    "reason": "targetAlreadyAbsent",
                }),
                audit_outcome: "FAILURE",
                audit_severity: "WARN",
                audit_event: EndUserAuditEvent {
                    event_type: "management.user.refreshTokenInventory.revocationFailed.v1",
                    target_id: user_id,
                    data: serde_json::json!({
                        "userId": user_id.to_string(),
                        "refreshTokenId": refresh_token_id,
                        "reason": "targetAlreadyAbsent",
                    }),
                },
            },
        )
        .await?;
        return Err(refresh_token_not_found(request_id));
    }

    write_user_management_runtime_command_outcome(
        context,
        request_id,
        EndUserRuntimeCommandOutcome {
            command_id,
            status: EndUserRuntimeCommandStatus::Applied,
            phase: "tokenStore",
            result: serde_json::json!({
                "revoked": true,
            }),
            audit_outcome: "SUCCESS",
            audit_severity: "INFO",
            audit_event: EndUserAuditEvent {
                event_type: "management.user.refreshTokenInventory.revocationApplied.v1",
                target_id: user_id,
                data: serde_json::json!({
                    "userId": user_id.to_string(),
                    "refreshTokenId": refresh_token_id,
                }),
            },
        },
    )
    .await?;

    Ok(())
}

fn refresh_token_not_found(request_id: &str) -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "Refresh token not found",
        None,
        Some(request_id),
    )
}

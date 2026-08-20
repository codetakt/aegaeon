use super::super::super::super::user_inventory_support::user_runtime_store_error_response;
use super::super::super::super::{
    begin_management_transaction, commit_management_transaction,
    insert_user_management_runtime_command, load_managed_user_identity,
    mark_user_management_runtime_command_executing, write_user_management_audit_event_with_outcome,
    write_user_management_runtime_command_outcome, AppState, EndUserAuditEvent,
    EndUserRuntimeCommandOutcome, EndUserRuntimeCommandStatus, UserManagementContext,
};
use axum::response::Response;
use uuid::Uuid;

#[expect(
    clippy::too_many_lines,
    reason = "existing transactional workflow; new oversized functions remain gated"
)]
pub(in crate::web::management::user_inventory::refresh_tokens) async fn revoke_user_refresh_tokens_inner(
    state: &AppState,
    context: &UserManagementContext,
    user_id: Uuid,
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
    let command_payload = serde_json::json!({
        "userId": user_id.to_string(),
    });
    let mut tx = begin_management_transaction(&context.pool, request_id).await?;
    context
        .require_lifecycle_role_in_transaction(&mut tx, request_id)
        .await?;
    let command_id = insert_user_management_runtime_command(
        &mut tx,
        context,
        request_id,
        "management.user.refresh_tokens.revoke_all",
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
            event_type: "management.user.refreshTokens.revocationRequested.v1",
            target_id: user_id,
            data: command_payload,
        },
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;
    mark_user_management_runtime_command_executing(context, request_id, command_id, "tokenStore")
        .await?;

    let revoked_count_result = state
        .tokens
        .store
        .try_revoke_tokens_by_subject_async(identity.subject.clone())
        .await;
    let revoked_count = match revoked_count_result {
        Ok(revoked_count) => revoked_count,
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
                        event_type: "management.user.refreshTokens.revocationFailed.v1",
                        target_id: user_id,
                        data: serde_json::json!({
                            "userId": user_id.to_string(),
                            "reason": "runtimeStoreUnavailable",
                        }),
                    },
                },
            )
            .await?;
            return Err(user_runtime_store_error_response(
                "token store",
                &err,
                "Token revocation store unavailable; operation not fully confirmed",
                request_id,
            ));
        }
    };

    tracing::info!(
        target: "management",
        request_id,
        user_id = %user_id,
        revoked_token_count = revoked_count,
        "user refresh token revocation completed after audit gate"
    );
    write_user_management_runtime_command_outcome(
        context,
        request_id,
        EndUserRuntimeCommandOutcome {
            command_id,
            status: EndUserRuntimeCommandStatus::Applied,
            phase: "tokenStore",
            result: serde_json::json!({
                "revokedTokenCount": revoked_count,
            }),
            audit_outcome: "SUCCESS",
            audit_severity: "INFO",
            audit_event: EndUserAuditEvent {
                event_type: "management.user.refreshTokens.revocationApplied.v1",
                target_id: user_id,
                data: serde_json::json!({
                    "userId": user_id.to_string(),
                    "revokedTokenCount": revoked_count,
                }),
            },
        },
    )
    .await?;
    Ok(())
}

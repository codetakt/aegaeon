use super::super::super::super::user_inventory_support::{
    find_user_grant_target, user_runtime_store_error_response,
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

pub(in crate::web::management::user_inventory::grants) async fn revoke_user_grant_inner(
    state: &AppState,
    context: &UserManagementContext,
    user_id: Uuid,
    grant_id: &str,
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
    let target = find_user_grant_target(state, &identity.subject, grant_id, request_id)
        .await?
        .ok_or_else(|| grant_not_found(request_id))?;

    let command_payload = serde_json::json!({
        "userId": user_id.to_string(),
        "grantId": grant_id,
        "source": target.source,
    });
    let mut tx = begin_management_transaction(&context.pool, request_id).await?;
    context
        .require_lifecycle_role_in_transaction(&mut tx, request_id)
        .await?;
    let command_id = insert_user_management_runtime_command(
        &mut tx,
        context,
        request_id,
        "management.user.grant.revoke",
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
            event_type: "management.user.grant.revocationRequested.v1",
            target_id: user_id,
            data: command_payload,
        },
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;
    mark_user_management_runtime_command_executing(context, request_id, command_id, "tokenStore")
        .await?;

    let revoked_result = if target.source == "refresh_token" {
        state
            .tokens
            .store
            .try_revoke_refresh_token_for_subject_async(
                identity.subject.clone(),
                target.raw_token_id,
            )
            .await
    } else {
        state
            .tokens
            .store
            .try_revoke_access_token_for_subject_async(
                identity.subject.clone(),
                target.raw_token_id,
            )
            .await
    };
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
                        event_type: "management.user.grant.revocationFailed.v1",
                        target_id: user_id,
                        data: serde_json::json!({
                            "userId": user_id.to_string(),
                            "grantId": grant_id,
                            "source": target.source,
                            "reason": "runtimeStoreUnavailable",
                        }),
                    },
                },
            )
            .await?;
            return Err(user_runtime_store_error_response(
                "token store",
                &err,
                "Grant revocation store unavailable",
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
                    event_type: "management.user.grant.revocationFailed.v1",
                    target_id: user_id,
                    data: serde_json::json!({
                        "userId": user_id.to_string(),
                        "grantId": grant_id,
                        "source": target.source,
                        "reason": "targetAlreadyAbsent",
                    }),
                },
            },
        )
        .await?;
        return Err(grant_not_found(request_id));
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
                event_type: "management.user.grant.revocationApplied.v1",
                target_id: user_id,
                data: serde_json::json!({
                    "userId": user_id.to_string(),
                    "grantId": grant_id,
                    "source": target.source,
                }),
            },
        },
    )
    .await?;

    Ok(())
}

fn grant_not_found(request_id: &str) -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "Grant not found",
        None,
        Some(request_id),
    )
}

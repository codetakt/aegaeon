use super::oidc::{dispatch_oidc_logout_events, logout_oidc_sessions_for_user};
use crate::web::management::user_inventory_support::user_runtime_store_error_response;
use crate::web::management::{
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
pub(in crate::web::management::user_inventory::sessions) async fn invalidate_user_sessions_inner(
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
        "management.user.sessions.invalidate",
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
            event_type: "management.user.sessions.invalidationRequested.v1",
            target_id: user_id,
            data: command_payload,
        },
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;
    mark_user_management_runtime_command_executing(
        context,
        request_id,
        command_id,
        "authSessionStore",
    )
    .await?;

    let revoked_sessions_result = state
        .browser_auth
        .auth_sessions
        .try_delete_for_user_async(identity.subject.clone())
        .await;
    let revoked_sessions = match revoked_sessions_result {
        Ok(revoked_sessions) => revoked_sessions,
        Err(err) => {
            write_user_management_runtime_command_outcome(
                context,
                request_id,
                EndUserRuntimeCommandOutcome {
                    command_id,
                    status: EndUserRuntimeCommandStatus::FailedUnconfirmed,
                    phase: "authSessionStore",
                    result: serde_json::json!({
                        "reason": "runtimeStoreUnavailable",
                    }),
                    audit_outcome: "FAILURE",
                    audit_severity: "ERROR",
                    audit_event: EndUserAuditEvent {
                        event_type: "management.user.sessions.invalidationFailed.v1",
                        target_id: user_id,
                        data: serde_json::json!({
                            "userId": user_id.to_string(),
                            "phase": "authSessionStore",
                            "reason": "runtimeStoreUnavailable",
                        }),
                    },
                },
            )
            .await?;
            return Err(user_runtime_store_error_response(
                "auth session store",
                &err,
                "Session invalidation store unavailable; operation aborted",
                request_id,
            ));
        }
    };
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
                        "revokedAuthSessions": revoked_sessions,
                    }),
                    audit_outcome: "FAILURE",
                    audit_severity: "ERROR",
                    audit_event: EndUserAuditEvent {
                        event_type: "management.user.sessions.invalidationFailed.v1",
                        target_id: user_id,
                        data: serde_json::json!({
                            "userId": user_id.to_string(),
                            "phase": "tokenStore",
                            "reason": "runtimeStoreUnavailable",
                            "revokedAuthSessions": revoked_sessions,
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
    let logout_events =
        match logout_oidc_sessions_for_user(state, &identity.subject, request_id).await {
            Ok(logout_events) => logout_events,
            Err(response) => {
                write_user_management_runtime_command_outcome(
                    context,
                    request_id,
                    EndUserRuntimeCommandOutcome {
                        command_id,
                        status: EndUserRuntimeCommandStatus::FailedUnconfirmed,
                        phase: "oidcSessionStore",
                        result: serde_json::json!({
                            "reason": "runtimeStoreUnavailable",
                            "revokedAuthSessions": revoked_sessions,
                            "revokedTokenCount": revoked_count,
                        }),
                        audit_outcome: "FAILURE",
                        audit_severity: "ERROR",
                        audit_event: EndUserAuditEvent {
                            event_type: "management.user.sessions.invalidationFailed.v1",
                            target_id: user_id,
                            data: serde_json::json!({
                                "userId": user_id.to_string(),
                                "phase": "oidcSessionStore",
                                "reason": "runtimeStoreUnavailable",
                                "revokedAuthSessions": revoked_sessions,
                                "revokedTokenCount": revoked_count,
                            }),
                        },
                    },
                )
                .await?;
                return Err(response);
            }
        };
    let oidc_logout_count = logout_events.len();
    dispatch_oidc_logout_events(state, logout_events).await;

    tracing::info!(
        target: "management",
        request_id,
        user_id = %user_id,
        revoked_auth_sessions = revoked_sessions,
        revoked_token_count = revoked_count,
        oidc_logout_count,
        "user session invalidation completed after audit gate"
    );
    write_user_management_runtime_command_outcome(
        context,
        request_id,
        EndUserRuntimeCommandOutcome {
            command_id,
            status: EndUserRuntimeCommandStatus::Applied,
            phase: "oidcSessionStore",
            result: serde_json::json!({
                "revokedAuthSessions": revoked_sessions,
                "revokedTokenCount": revoked_count,
                "oidcLogoutCount": oidc_logout_count,
            }),
            audit_outcome: "SUCCESS",
            audit_severity: "INFO",
            audit_event: EndUserAuditEvent {
                event_type: "management.user.sessions.invalidationApplied.v1",
                target_id: user_id,
                data: serde_json::json!({
                    "userId": user_id.to_string(),
                    "revokedAuthSessions": revoked_sessions,
                    "revokedTokenCount": revoked_count,
                    "oidcLogoutCount": oidc_logout_count,
                }),
            },
        },
    )
    .await?;
    Ok(())
}

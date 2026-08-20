use super::oidc::{dispatch_oidc_logout_events, logout_oidc_session_for_auth_session};
use crate::web::management::user_inventory_support::{
    find_user_session_raw_id, user_runtime_store_error_response,
};
use crate::web::management::{
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
pub(in crate::web::management::user_inventory::sessions) async fn revoke_user_session_inner(
    state: &AppState,
    context: &UserManagementContext,
    user_id: Uuid,
    session_inventory_id: &str,
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
    let raw_session_id =
        find_user_session_raw_id(state, &identity.subject, session_inventory_id, request_id)
            .await?
            .ok_or_else(|| session_not_found_response(request_id))?;
    let command_payload = serde_json::json!({
        "userId": user_id.to_string(),
        "sessionId": session_inventory_id,
    });
    let mut tx = begin_management_transaction(&context.pool, request_id).await?;
    context
        .require_lifecycle_role_in_transaction(&mut tx, request_id)
        .await?;
    let command_id = insert_user_management_runtime_command(
        &mut tx,
        context,
        request_id,
        "management.user.session.revoke",
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
            event_type: "management.user.session.revocationRequested.v1",
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

    let deleted_result = state
        .browser_auth
        .auth_sessions
        .try_delete_for_user_session_async(identity.subject.clone(), raw_session_id.clone())
        .await;
    let deleted = match deleted_result {
        Ok(deleted) => deleted,
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
                        event_type: "management.user.session.revocationFailed.v1",
                        target_id: user_id,
                        data: serde_json::json!({
                            "userId": user_id.to_string(),
                            "sessionId": session_inventory_id,
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
                "Session inventory store unavailable",
                request_id,
            ));
        }
    };
    if !deleted {
        write_user_management_runtime_command_outcome(
            context,
            request_id,
            EndUserRuntimeCommandOutcome {
                command_id,
                status: EndUserRuntimeCommandStatus::FailedTerminal,
                phase: "authSessionStore",
                result: serde_json::json!({
                    "reason": "targetAlreadyAbsent",
                }),
                audit_outcome: "FAILURE",
                audit_severity: "WARN",
                audit_event: EndUserAuditEvent {
                    event_type: "management.user.session.revocationFailed.v1",
                    target_id: user_id,
                    data: serde_json::json!({
                        "userId": user_id.to_string(),
                        "sessionId": session_inventory_id,
                        "phase": "authSessionStore",
                        "reason": "targetAlreadyAbsent",
                    }),
                },
            },
        )
        .await?;
        return Err(session_not_found_response(request_id));
    }
    let logout_events =
        match logout_oidc_session_for_auth_session(state, &raw_session_id, request_id).await {
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
                            "authSessionDeleted": true,
                        }),
                        audit_outcome: "FAILURE",
                        audit_severity: "ERROR",
                        audit_event: EndUserAuditEvent {
                            event_type: "management.user.session.revocationFailed.v1",
                            target_id: user_id,
                            data: serde_json::json!({
                                "userId": user_id.to_string(),
                                "sessionId": session_inventory_id,
                                "phase": "oidcSessionStore",
                                "reason": "runtimeStoreUnavailable",
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
    write_user_management_runtime_command_outcome(
        context,
        request_id,
        EndUserRuntimeCommandOutcome {
            command_id,
            status: EndUserRuntimeCommandStatus::Applied,
            phase: "oidcSessionStore",
            result: serde_json::json!({
                "authSessionDeleted": true,
                "oidcLogoutCount": oidc_logout_count,
            }),
            audit_outcome: "SUCCESS",
            audit_severity: "INFO",
            audit_event: EndUserAuditEvent {
                event_type: "management.user.session.revocationApplied.v1",
                target_id: user_id,
                data: serde_json::json!({
                    "userId": user_id.to_string(),
                    "sessionId": session_inventory_id,
                    "oidcLogoutCount": oidc_logout_count,
                }),
            },
        },
    )
    .await?;

    Ok(())
}

fn session_not_found_response(request_id: &str) -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "Session not found",
        None,
        Some(request_id),
    )
}

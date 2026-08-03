use super::super::super::super::super::{
    begin_management_transaction, commit_management_transaction, UserManagementContext,
};
use super::super::super::super::audit::write_user_change_audit_event;
use super::super::super::super::store::{
    load_user_row_for_status, update_user_status_row, UserStatusUpdateMessages,
};
use crate::management::types::User;
use axum::response::Response;
use uuid::Uuid;

pub(super) struct UserStatusTransition {
    pub(super) required_status_filter: &'static str,
    pub(super) update_clause: &'static str,
    pub(super) not_found_message: &'static str,
    pub(super) failure_message: &'static str,
    pub(super) audit_event_type: &'static str,
}

pub(super) async fn transition_user_status(
    context: &UserManagementContext,
    user_id: Uuid,
    request_id: &str,
    transition: UserStatusTransition,
) -> Result<User, Response> {
    let mut tx = begin_management_transaction(&context.pool, request_id).await?;
    context
        .require_lifecycle_role_in_transaction(&mut tx, request_id)
        .await?;
    let previous_user = load_user_row_for_status(
        &mut *tx,
        context,
        user_id,
        transition.required_status_filter,
        transition.not_found_message,
        request_id,
    )
    .await?;
    let user = update_user_status_row(
        &mut *tx,
        context,
        user_id,
        transition.required_status_filter,
        transition.update_clause,
        UserStatusUpdateMessages {
            not_found_message: transition.not_found_message,
            failure_message: transition.failure_message,
        },
        request_id,
    )
    .await?;
    write_user_change_audit_event(
        &mut tx,
        context,
        request_id,
        transition.audit_event_type,
        user_id,
        &previous_user,
        &user,
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;

    Ok(user)
}

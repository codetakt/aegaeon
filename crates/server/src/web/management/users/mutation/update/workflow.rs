use super::super::super::super::{
    begin_management_transaction, commit_management_transaction, UserManagementContext,
};
use super::super::super::audit::write_user_change_audit_event;
use super::super::super::store::{
    build_user_update_patch, load_user_row_for_status, update_user_fields_row,
};
use crate::management::types::{UpdateUserRequest, User};
use axum::response::Response;
use uuid::Uuid;

pub(super) async fn update_user_inner(
    context: &UserManagementContext,
    user_id: Uuid,
    body: &UpdateUserRequest,
    request_id: &str,
) -> Result<User, Response> {
    let patch = build_user_update_patch(body, request_id)?;
    let mut tx = begin_management_transaction(&context.pool, request_id).await?;
    context
        .require_lifecycle_role_in_transaction(&mut tx, request_id)
        .await?;
    let previous_user = load_user_row_for_status(
        &mut *tx,
        context,
        user_id,
        "AND u.status <> 'DELETED'",
        "User not found",
        request_id,
    )
    .await?;
    let user = update_user_fields_row(&mut tx, context, user_id, &patch, request_id).await?;
    write_user_change_audit_event(
        &mut tx,
        context,
        request_id,
        "management.user.updated.v1",
        user_id,
        &previous_user,
        &user,
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;

    Ok(user)
}

use super::super::super::super::{
    commit_management_transaction, management_internal_error, UserManagementContext,
};
use super::super::super::audit::write_user_change_audit_event;
use super::super::super::store::{
    build_user_update_patch, load_user_row_for_status, update_user_fields_row,
};
use crate::dcr_persistence::admitted_connection::AdmittedConnection;
use crate::management::types::{UpdateUserRequest, User};
use crate::organizations::request_work::async_store;
use axum::response::Response;
use sqlx::Connection;
use uuid::Uuid;

mod history;

pub(super) async fn current(
    context: &UserManagementContext,
    user_id: Uuid,
    request_id: &str,
) -> Result<User, Response> {
    use crate::web::management::request_support::owned;
    async_store::ensure_environment_if_scoped(context.environment_id)
        .map_err(|_| owned::unavailable(request_id))?;
    let mut connection = owned::connection(&context.pool)
        .await
        .map_err(|_| owned::unavailable(request_id))?;
    let result = load_user_row_for_status(
        connection
            .as_mut()
            .map_err(|_| owned::unavailable(request_id))?,
        context,
        user_id,
        "AND u.status <> 'DELETED'",
        "User not found",
        request_id,
    )
    .await;
    connection.release().await;
    owned::scoped().map_err(|_| owned::unavailable(request_id))?;
    result
}

pub(super) async fn update_user_inner(
    context: &UserManagementContext,
    user_id: Uuid,
    body: &UpdateUserRequest,
    request_id: &str,
) -> Result<User, Response> {
    let patch = build_user_update_patch(body, request_id)?;
    async_store::ensure_environment_if_scoped(context.environment_id)
        .map_err(|_| history::unavailable(request_id))?;
    if let Some(subject) = patch.subject() {
        history::reserve(context, user_id, subject, request_id).await?;
    }
    let mut connection = AdmittedConnection::acquire(&context.pool)
        .await
        .map_err(|_| history::unavailable(request_id))?;
    let result = async {
        let mut tx = connection
            .as_mut()
            .map_err(|_| history::unavailable(request_id))?
            .begin()
            .await
            .map_err(|_| management_internal_error(request_id, "Failed to start transaction"))?;
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
        async_store::admit_current_commit().map_err(|_| history::unavailable(request_id))?;
        commit_management_transaction(tx, request_id).await?;

        Ok(user)
    }
    .await;
    connection.release().await;
    async_store::ensure_environment_if_scoped(context.environment_id)
        .map_err(|_| history::unavailable(request_id))?;
    result
}

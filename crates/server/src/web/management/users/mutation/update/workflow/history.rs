//! Authorization reads finish before independent reservation and primary writes.
use super::*;
use crate::organizations::witness::Error;
use crate::web::management::error_response;
use axum::http::StatusCode;

pub(super) fn unavailable(request_id: &str) -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "User identity history unavailable",
        None,
        Some(request_id),
    )
}

fn failure(error: &Error, request_id: &str) -> Response {
    if matches!(error, Error::Storage(sqlx::Error::Database(error))
        if matches!(error.message(), "permanent owner conflict" | "permanent subject conflict"))
    {
        return error_response(
            StatusCode::CONFLICT,
            "conflict",
            "Subject ownership conflict",
            None,
            Some(request_id),
        );
    }
    unavailable(request_id)
}

pub(super) async fn reserve(
    context: &UserManagementContext,
    user_id: Uuid,
    subject: &str,
    request_id: &str,
) -> Result<(), Response> {
    let Some(owner) = async_store::task_owner().map_err(|_| unavailable(request_id))? else {
        return Ok(());
    };
    async_store::ensure_environment_if_scoped(context.environment_id)
        .map_err(|_| unavailable(request_id))?;
    let mut connection = AdmittedConnection::acquire(&context.pool)
        .await
        .map_err(|_| unavailable(request_id))?;
    let result = async {
        let mut tx = connection
            .as_mut()
            .map_err(|_| unavailable(request_id))?
            .begin()
            .await
            .map_err(|_| unavailable(request_id))?;
        context
            .require_lifecycle_role_in_transaction(&mut tx, request_id)
            .await?;
        let previous = load_user_row_for_status(
            &mut *tx,
            context,
            user_id,
            "AND u.status <> 'DELETED'",
            "User not found",
            request_id,
        )
        .await?;
        tx.rollback().await.map_err(|_| unavailable(request_id))?;
        Ok::<_, Response>(previous)
    }
    .await;
    connection.release().await;
    let previous = result?;
    owner
        .check_history(context.environment_id, user_id, &previous.subject)
        .await
        .map_err(|error| failure(&error, request_id))?;
    owner
        .reserve_history(context.environment_id, user_id, subject)
        .await
        .map_err(|error| failure(&error, request_id))?;
    Ok(())
}

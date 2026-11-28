use super::super::store::load_user_row_for_status;
use crate::organizations::operators::mutations::identity_policy;
use crate::web::management::{
    begin_management_transaction, commit_management_transaction,
    http_errors::management_database_error, require_user_id_param, require_user_management_context,
    transactions, write_user_management_audit_event, AppState, EndUserAuditEvent, RequestContext,
    TeamEnvironmentUserPath, UserManagementContext,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension,
};
use uuid::Uuid;
mod contact;

pub(in crate::web::management::users) async fn finalize_withdrawal(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<TeamEnvironmentUserPath>,
) -> Response {
    let context =
        match require_user_management_context(&state, &headers, &params, &ctx.request_id).await {
            Ok(context) => context,
            Err(resp) => return resp,
        };
    let user_id = match require_user_id_param(&params, &ctx.request_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match finalize_withdrawal_inner(&context, user_id, &ctx.request_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(resp) => resp,
    }
}

async fn finalize_withdrawal_inner(
    context: &UserManagementContext,
    user_id: Uuid,
    request_id: &str,
) -> Result<(), Response> {
    let mut connection = transactions::connection(&context.pool, request_id).await?;
    let mut tx = begin_management_transaction(&mut connection, request_id).await?;
    let failure =
        |error| management_database_error(request_id, &error, "Could not finalize withdrawal");
    identity_policy::lock_environment(&mut tx, context.environment_id)
        .await
        .map_err(failure)?;
    context
        .require_lifecycle_role_in_transaction(&mut tx, request_id)
        .await?;
    let user = load_user_row_for_status(
        &mut *tx,
        context,
        user_id,
        "AND u.status = 'DELETED'",
        "Deleted user not found",
        request_id,
    )
    .await?;
    if contact::release(
        &mut tx,
        context.environment_id,
        user_id,
        user.email,
        context.session.administrator_id,
    )
    .await
    .map_err(failure)?
    {
        write_user_management_audit_event(
            &mut tx,
            context,
            request_id,
            EndUserAuditEvent {
                event_type: "management.user.withdrawal_finalized.v1",
                target_id: user_id,
                data: serde_json::json!({"userId": user_id}),
            },
        )
        .await?;
    }
    let commit = commit_management_transaction(tx, request_id).await;
    transactions::finish(commit, connection, request_id).await
}

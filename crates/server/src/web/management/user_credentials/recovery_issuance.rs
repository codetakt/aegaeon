mod token;
mod workflow;

use super::super::{
    require_user_id_param, require_user_management_context, AppState, RequestContext,
};
use crate::local_credentials::RecoveryTokenPurpose;
use crate::management::types::IssueRecoveryTokenRequest;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};

pub(super) use token::issue_recovery_token_with_redeem_url;
use workflow::issue_recovery_token_inner;

async fn issue_recovery_token_handler(
    state: AppState,
    ctx: RequestContext,
    headers: HeaderMap,
    params: crate::web::management::TeamEnvironmentUserPath,
    body: IssueRecoveryTokenRequest,
    purpose: RecoveryTokenPurpose,
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

    match issue_recovery_token_inner(&context, user_id, &body, purpose, &ctx.request_id).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(resp) => resp,
    }
}

pub(super) async fn issue_activation_token(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentUserPath>,
    Json(body): Json<IssueRecoveryTokenRequest>,
) -> Response {
    issue_recovery_token_handler(
        state,
        ctx,
        headers,
        params,
        body,
        RecoveryTokenPurpose::Activation,
    )
    .await
}

pub(super) async fn issue_password_reset_token(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentUserPath>,
    Json(body): Json<IssueRecoveryTokenRequest>,
) -> Response {
    issue_recovery_token_handler(
        state,
        ctx,
        headers,
        params,
        body,
        RecoveryTokenPurpose::PasswordReset,
    )
    .await
}

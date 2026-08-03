mod workflow;

use super::super::super::{
    management_db_pool, require_human_management_session_async, AppState, RequestContext,
    RuntimeClientMutationSync,
};
use crate::management::types::ConfigurationTransactionRequest;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use workflow::revoke_client_secret_inner;

pub(in crate::web::management::client_secrets) async fn revoke_client_secret(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentClientSecretPath>,
    Json(req): Json<ConfigurationTransactionRequest>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session =
        match require_human_management_session_async(&state, &headers, &ctx.request_id).await {
            Ok(session) => session,
            Err(resp) => return resp,
        };
    match revoke_client_secret_inner(
        pool,
        RuntimeClientMutationSync::from_state(&state),
        &params,
        &req,
        &session,
        &ctx.request_id,
    )
    .await
    {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(resp) => resp,
    }
}

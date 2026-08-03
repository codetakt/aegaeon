mod workflow;

use super::super::super::{
    base_configuration_version_id_from_header, management_db_pool,
    require_human_management_session_async, AppState, RequestContext, RuntimeClientMutationSync,
    TeamEnvironmentClientPath,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension,
};
use workflow::{delete_client_inner, DeleteClientInput};

pub(in crate::web::management::clients) async fn delete_client(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(path): Path<TeamEnvironmentClientPath>,
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
    let (team_id, environment_id, client_id) = match path.ids(&ctx.request_id) {
        Ok(ids) => ids,
        Err(resp) => return resp,
    };
    let base_configuration_version_id =
        match base_configuration_version_id_from_header(&headers, &ctx.request_id) {
            Ok(value) => value,
            Err(resp) => return resp,
        };
    match delete_client_inner(DeleteClientInput {
        pool,
        runtime_sync: RuntimeClientMutationSync::from_state(&state),
        team_id,
        environment_id,
        client_id,
        base_configuration_version_id,
        session: &session,
        request_id: &ctx.request_id,
    })
    .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(resp) => resp,
    }
}

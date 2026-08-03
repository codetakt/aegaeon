use crate::management::types::ListUserSessionsResponse;
use crate::web::management::user_inventory_support::collect_user_sessions;
use crate::web::management::{load_managed_user_identity, AppState, UserManagementContext};
use axum::response::Response;
use uuid::Uuid;

pub(in crate::web::management::user_inventory::sessions) async fn list_user_sessions_inner(
    state: &AppState,
    context: &UserManagementContext,
    user_id: Uuid,
    request_id: &str,
) -> Result<ListUserSessionsResponse, Response> {
    let identity = load_managed_user_identity(
        &context.pool,
        context.team_id,
        context.environment_id,
        user_id,
        request_id,
    )
    .await?;

    Ok(ListUserSessionsResponse {
        sessions: collect_user_sessions(state, &identity.subject, request_id).await?,
        page_info: None,
    })
}

use super::super::super::super::user_inventory_support::collect_user_refresh_tokens;
use super::super::super::super::{load_managed_user_identity, AppState, UserManagementContext};
use crate::management::types::ListUserRefreshTokensResponse;
use axum::response::Response;
use uuid::Uuid;

pub(in crate::web::management::user_inventory::refresh_tokens) async fn list_user_refresh_tokens_inner(
    state: &AppState,
    context: &UserManagementContext,
    user_id: Uuid,
    request_id: &str,
) -> Result<ListUserRefreshTokensResponse, Response> {
    let identity = load_managed_user_identity(
        &context.pool,
        context.team_id,
        context.environment_id,
        user_id,
        request_id,
    )
    .await?;

    Ok(ListUserRefreshTokensResponse {
        refresh_tokens: collect_user_refresh_tokens(state, &identity.subject, request_id).await?,
        page_info: None,
    })
}

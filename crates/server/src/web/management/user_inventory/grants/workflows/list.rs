use super::super::super::super::user_inventory_support::collect_user_grants;
use super::super::super::super::{load_managed_user_identity, AppState, UserManagementContext};
use crate::management::types::ListUserGrantsResponse;
use axum::response::Response;
use uuid::Uuid;

pub(in crate::web::management::user_inventory::grants) async fn list_user_grants_inner(
    state: &AppState,
    context: &UserManagementContext,
    user_id: Uuid,
    request_id: &str,
) -> Result<ListUserGrantsResponse, Response> {
    let identity = load_managed_user_identity(
        &context.pool,
        context.team_id,
        context.environment_id,
        user_id,
        request_id,
    )
    .await?;

    Ok(ListUserGrantsResponse {
        grants: collect_user_grants(state, &identity.subject, request_id).await?,
        page_info: None,
    })
}

use crate::management::types::KeyStorePublicView;
use crate::web::management::{
    ensure_team_visible, error_response, parse_team_environment_scope, state::ManagementSession,
};
use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;

use super::super::store::{key_store_public_view_from_row_result, load_key_store_row};

fn key_store_not_found(request_id: &str) -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "Key store not found",
        None,
        Some(request_id),
    )
}

pub(in crate::web::management) async fn get_key_store_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentPath,
    session: &ManagementSession,
    request_id: &str,
) -> Result<KeyStorePublicView, Response> {
    let (team_id, environment_id) = parse_team_environment_scope(params, request_id)?;
    ensure_team_visible(pool, team_id, session, request_id).await?;

    let Some(row) = load_key_store_row(pool, team_id, environment_id, request_id).await? else {
        return Err(key_store_not_found(request_id));
    };
    key_store_public_view_from_row_result(&row, request_id)
}

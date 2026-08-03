use super::super::store::list_client_secret_rows;
use crate::management::types::ListClientSecretsResponse;
use crate::web::management::{
    client_secret_from_row_result, ensure_team_visible, parse_team_environment_client_scope,
    state::ManagementSession,
};
use axum::response::Response;
use sqlx::PgPool;

pub(super) async fn list_client_secrets_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentClientPath,
    session: &ManagementSession,
    request_id: &str,
) -> Result<ListClientSecretsResponse, Response> {
    let (team_id, environment_id, client_id) =
        parse_team_environment_client_scope(params, request_id)?;
    ensure_team_visible(pool, team_id, session, request_id).await?;

    let rows =
        list_client_secret_rows(pool, team_id, environment_id, client_id, request_id).await?;
    let client_secrets = rows
        .iter()
        .map(|row| client_secret_from_row_result(row, request_id))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ListClientSecretsResponse {
        client_secrets,
        page_info: None,
    })
}

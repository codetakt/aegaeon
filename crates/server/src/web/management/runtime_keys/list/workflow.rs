use crate::management::types::ListRuntimeKeysResponse;
use crate::web::management::runtime_key_store::{list_runtime_key_rows, runtime_key_from_row};
use crate::web::management::{ensure_team_visible, state::ManagementSession, TeamEnvironmentPath};
use axum::response::Response;
use sqlx::PgPool;

pub(super) async fn list_runtime_keys_inner(
    pool: &PgPool,
    path: &TeamEnvironmentPath,
    session: &ManagementSession,
    request_id: &str,
) -> Result<ListRuntimeKeysResponse, Response> {
    let (team_id, environment_id) = path.ids(request_id)?;
    ensure_team_visible(pool, team_id, session, request_id).await?;

    let rows = list_runtime_key_rows(pool, team_id, environment_id, request_id).await?;
    let runtime_keys = rows
        .iter()
        .map(|row| runtime_key_from_row(row, request_id))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ListRuntimeKeysResponse {
        runtime_keys,
        page_info: None,
    })
}

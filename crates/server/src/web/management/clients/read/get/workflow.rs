use crate::management::types::Client;
use crate::web::management::client_store::{client_not_found, load_visible_client};
use crate::web::management::{ensure_team_visible, state::ManagementSession};
use axum::response::Response;
use sqlx::PgPool;
use uuid::Uuid;

pub(in crate::web::management) async fn get_client_inner(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    client_id: Uuid,
    session: &ManagementSession,
    request_id: &str,
) -> Result<Client, Response> {
    ensure_team_visible(pool, team_id, session, request_id).await?;

    let Some(client) =
        load_visible_client(pool, team_id, environment_id, client_id, request_id).await?
    else {
        return Err(client_not_found(request_id));
    };

    Ok(client)
}

use crate::management::types::Connection;
use crate::web::management::connections_store::{connection_not_found, load_connection};
use crate::web::management::state::ManagementSession;
use crate::web::management::{ensure_team_visible_as, parse_team_environment_connection_scope};
use axum::response::Response;
use sqlx::PgPool;

pub(in crate::web::management) async fn get_connection_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentConnectionPath,
    session: &ManagementSession,
    request_id: &str,
) -> Result<Connection, Response> {
    let (team_id, environment_id, connection_id) =
        parse_team_environment_connection_scope(params, request_id)?;
    ensure_team_visible_as(pool, team_id, session, request_id, connection_not_found).await?;

    let Some(connection) =
        load_connection(pool, team_id, environment_id, connection_id, request_id).await?
    else {
        return Err(connection_not_found(request_id));
    };

    Ok(connection)
}

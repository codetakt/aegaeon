use super::super::{error_response, load_environment_row, management_internal_error};
use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;
use uuid::Uuid;

pub(super) async fn load_environment_issuer_url(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    request_id: &str,
) -> Result<String, Response> {
    let Some((_tenant_id, _name, _slug, _issuer_host, issuer_url, _active, _created, _updated)) =
        load_environment_row(pool, team_id, environment_id)
            .await
            .map_err(|_| management_internal_error(request_id, "Database query failed"))?
    else {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Environment not found",
            None,
            Some(request_id),
        ));
    };

    Ok(issuer_url)
}

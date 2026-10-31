//! Shared management work inherits only an explicitly bound live task.
use crate::{
    dcr_persistence::admitted_connection::AdmittedConnection,
    organizations::request_work::async_store,
};
use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;

pub(in crate::web::management) fn scoped() -> Result<bool, sqlx::Error> {
    let Some(owner) = async_store::task_owner()? else {
        return Ok(false);
    };
    owner.epoch_binding()?;
    owner.require_store_scope()?;
    Ok(true)
}

pub(in crate::web::management) async fn connection(
    pool: &PgPool,
) -> Result<AdmittedConnection, sqlx::Error> {
    scoped()?;
    AdmittedConnection::acquire(pool).await
}

pub(in crate::web::management) fn unavailable(request_id: &str) -> Response {
    super::super::error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "Management request admission unavailable",
        None,
        Some(request_id),
    )
}

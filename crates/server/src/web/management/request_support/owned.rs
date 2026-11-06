//! Shared management work inherits only an explicitly bound live task.
pub(in crate::web::management) mod reads;
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
    owner.require_management_binding()?;
    Ok(true)
}

pub(in crate::web::management) async fn connection(
    pool: &PgPool,
) -> Result<AdmittedConnection, sqlx::Error> {
    scoped()?;
    AdmittedConnection::acquire(pool).await
}

#[track_caller]
pub(in crate::web::management) fn unavailable(request_id: &str) -> Response {
    let site = std::panic::Location::caller();
    tracing::error!(target: "management_database", request_id,
        source_file = site.file(), source_line = site.line(),
        "management database admission unavailable");
    super::super::error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "Management request admission unavailable",
        None,
        Some(request_id),
    )
}

use super::error::storage_err;
use crate::dcr_persistence::admitted_connection::AdmittedConnection;
use crate::federation::FederationError;
use sqlx::PgPool;
use uuid::Uuid;

pub(super) fn environment(expected: Option<Uuid>) -> Result<Option<Uuid>, FederationError> {
    let Some(owner) = crate::organizations::request_work::async_store::task_owner()
        .map_err(|e| storage_err(&e))?
    else {
        return Ok(None);
    };
    owner.require_store_scope().map_err(|e| storage_err(&e))?;
    let actual = owner
        .epoch_binding()
        .map_err(|e| storage_err(&e))?
        .environment_id();
    if expected.is_some_and(|id| id != actual) {
        return Err(FederationError::Storage(
            "foreign Organizations federation Environment".into(),
        ));
    }
    Ok(Some(actual))
}

pub(super) async fn acquire(
    pool: &PgPool,
    expected: Option<Uuid>,
) -> Result<AdmittedConnection, FederationError> {
    environment(expected)?;
    AdmittedConnection::acquire(pool)
        .await
        .map_err(|e| storage_err(&e))
}

pub(super) fn commit() -> Result<(), FederationError> {
    crate::organizations::request_work::async_store::admit_current_commit()
        .map_err(|e| storage_err(&e))
}

pub(super) async fn finish<T>(
    connection: AdmittedConnection,
    result: Result<T, FederationError>,
    expected: Option<Uuid>,
) -> Result<T, FederationError> {
    connection.release().await;
    environment(expected)?;
    result
}

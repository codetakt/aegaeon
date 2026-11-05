//! Validate the actual retained runtime connection; the caller supplies transport.
use super::{Error, Result, STEP};
use crate::organizations::store_observation::Postgres;
use sqlx::PgConnection;
use uuid::Uuid;

pub(crate) async fn checked(
    mut connection: PgConnection,
    environment: Uuid,
    issuer: &str,
) -> Result<Postgres> {
    tokio::time::timeout(
        STEP,
        crate::web::namespace_runtime::validate_connection_inputs(
            &mut connection,
            environment,
            issuer,
        ),
    )
    .await
    .map_err(|_| Error::Deadline)?
    .map_err(|_| Error::Refused)?;
    Postgres::observe(connection)
        .await
        .map_err(|_| Error::Refused)
}

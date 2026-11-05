//! Actual store observations. These are diagnostic evidence, never admission,
//! nonrollback qualification, completion receipts or activation capabilities.
#[cfg(test)]
use std::time::Duration;

#[cfg(test)]
pub mod cli;
#[cfg(test)]
mod continuity;
#[cfg(test)]
mod credentials;
#[cfg(test)]
mod postgres;
#[cfg(test)]
mod redis;
pub(in crate::organizations) mod transport;
#[cfg(test)]
pub use postgres::{Postgres, PostgresObservation};
#[cfg(test)]
pub use redis::{Redis, RedisObservation};

#[cfg(test)]
const DEADLINE: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
#[cfg(test)]
pub enum Error {
    #[error("Organizations store observation refused")]
    Refused,
    #[error("Organizations store observation deadline")]
    Deadline,
    #[error("Organizations primary observation unavailable")]
    Postgres(#[from] sqlx::Error),
    #[error("Organizations token-store observation unavailable")]
    Redis(#[from] ::redis::RedisError),
}
#[cfg(test)]
type Result<T> = std::result::Result<T, Error>;

/// Inspect the actual borrowed data connection inside its existing work owner.
#[cfg(test)]
pub(crate) async fn primary(connection: &mut sqlx::PgConnection) -> Result<PostgresObservation> {
    tokio::time::timeout(DEADLINE, postgres::read(connection))
        .await
        .map_err(|_| Error::Deadline)?
}
#[cfg(test)]
pub(crate) async fn token(
    connection: &mut ::redis::aio::MultiplexedConnection,
) -> Result<RedisObservation> {
    tokio::time::timeout(DEADLINE, redis::read(connection))
        .await
        .map_err(|_| Error::Deadline)?
}

#[cfg(test)]
mod tests;

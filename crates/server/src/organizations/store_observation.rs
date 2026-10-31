//! Actual store observations. These are diagnostic evidence, never admission,
//! nonrollback qualification, completion receipts or activation capabilities.
use std::time::Duration;

pub mod cli;
mod postgres;
mod redis;
pub use postgres::{Postgres, PostgresObservation};
pub use redis::{Redis, RedisObservation};

const DEADLINE: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
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
type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests;

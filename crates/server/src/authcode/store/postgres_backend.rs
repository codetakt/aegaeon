//! Native SQL transactions over current grant/capability rows.
use super::{token_consistency, PostgresGrantDatabase};
use crate::authcode::types::{AccessToken, BearerTokenMeta, RefreshGrantRecord, RefreshToken};
use crate::dcr_persistence::admitted_connection::AdmittedConnection;
use aegaeon_crypto::hash::sha256_digest;
use sqlx::{Connection, PgConnection};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod cleanup;
mod device;
mod exchange;
mod initial;
mod inventory;
mod locking;
mod retained;
mod revocation;
mod subject;
pub(super) use revocation::Owner;
mod reads;
mod records;
mod rotation;
#[cfg(test)]
mod tests;

#[derive(Clone)]
pub(super) struct PostgresTokenStoreBackend {
    database: PostgresGrantDatabase,
}

fn unavailable() -> String {
    "token database unavailable or invalid".into()
}

fn micros(value: SystemTime) -> Result<i64, String> {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|v| i64::try_from(v.as_micros()).ok())
        .filter(|v| *v > 0)
        .ok_or_else(unavailable)
}

async fn clock(connection: &mut PgConnection) -> Result<(i64, SystemTime), String> {
    let us: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch from clock_timestamp())*1000000)::bigint")
            .fetch_one(connection)
            .await
            .map_err(|_| unavailable())?;
    let time = UNIX_EPOCH
        .checked_add(Duration::from_micros(
            u64::try_from(us).map_err(|_| unavailable())?,
        ))
        .ok_or_else(unavailable)?;
    Ok((us, time))
}

fn encode(value: &impl serde::Serialize) -> Result<String, String> {
    let encoded = serde_json::to_string(value).map_err(|_| unavailable())?;
    if encoded.is_empty() || encoded.len() > 1_048_576 {
        return Err(unavailable());
    }
    Ok(encoded)
}

impl PostgresTokenStoreBackend {
    pub(super) fn new(database: PostgresGrantDatabase) -> Self {
        Self { database }
    }
}

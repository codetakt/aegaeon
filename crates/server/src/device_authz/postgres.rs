//! Current device authorization in the same database as token publication.
use crate::authcode::store::PostgresGrantDatabase;
use crate::dcr_persistence::admitted_connection::AdmittedConnection;
use aegaeon_crypto::hash::sha256_digest;
use sqlx::PgConnection;
use std::time::Duration;
mod creation;
pub(super) use creation::CreateRequest;
mod operations;
mod records;
pub(super) use operations::PollRequest;
mod maintenance;
pub(crate) use records::PostgresDeviceGrantCommit;
use records::Record;

#[derive(Clone)]
pub(super) struct PostgresDeviceCodeStore {
    database: PostgresGrantDatabase,
}
impl PostgresDeviceCodeStore {
    pub(super) fn new(database: PostgresGrantDatabase) -> Self {
        Self { database }
    }
}
fn unavailable() -> String {
    "device authorization database unavailable or invalid".into()
}
async fn clock(conn: &mut PgConnection) -> Result<i64, String> {
    sqlx::query_scalar("SELECT floor(extract(epoch from clock_timestamp())*1000000)::bigint")
        .fetch_one(conn)
        .await
        .map_err(|_| unavailable())
}

#[cfg(test)]
mod tests;

//! Native current JWKS security state; caller integration is tracked separately.
use super::super::JwksRuntimePolicy;
use crate::dcr_persistence::admitted_connection::AdmittedConnection;
use aegaeon_crypto::hash::sha256_digest;
use sqlx::{Connection, PgConnection, PgPool};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use uuid::Uuid;
mod acquisition;
mod completion;
mod current_body;
pub(in crate::client_registry) use completion::Completion;
#[cfg(test)]
mod tests;
const FETCH_LEASE_SECS: u64 = 30;
const MAX_BINDING_BYTES: usize = 1_048_576;
pub(in crate::client_registry) struct AdmittedKeys {
    fingerprints: HashMap<String, String>,
    body_digest: [u8; 32],
}

#[derive(Clone)]
pub(in crate::client_registry) struct PostgresJwksState {
    pool: PgPool,
    namespace: Arc<str>,
    identity: Arc<()>,
}
#[derive(Clone)]
pub(in crate::client_registry) struct FetchPermit {
    identity: Arc<()>,
    uri: [u8; 32],
    owner: Uuid,
    deadline: Instant,
    ttl_us: i64,
    reset_us: i64,
    threshold: u32,
    allow_reuse: bool,
}
impl FetchPermit {
    pub(in crate::client_registry) fn remaining(&self) -> Option<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|v| !v.is_zero())
    }
}
#[derive(Clone)]
struct Row {
    failures: i64,
    open_until: Option<i64>,
    owner: Option<Uuid>,
    lease_until: Option<i64>,
    expires: i64,
}
impl sqlx::FromRow<'_, sqlx::postgres::PgRow> for Row {
    fn from_row(row: &sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            failures: row.try_get("failures")?,
            open_until: row.try_get("open_until_us")?,
            owner: row.try_get("owner")?,
            lease_until: row.try_get("lease_until_us")?,
            expires: row.try_get("expires_us")?,
        })
    }
}
impl PostgresJwksState {
    pub(in crate::client_registry) async fn cleanup(&self) -> Result<(), String> {
        use crate::runtime_security_cleanup::{cleanup, Kind, PASS_BATCHES};
        for kind in [Kind::JwksBindings, Kind::JwksFetch] {
            cleanup(&self.pool, &self.namespace, kind, PASS_BATCHES).await?;
        }
        Ok(())
    }

    pub(in crate::client_registry) fn new(
        pool: PgPool,
        namespace: &crate::config::RuntimeStateNamespace,
    ) -> Self {
        Self {
            pool,
            namespace: namespace.flow_namespace("client", "jwks").into(),
            identity: Arc::new(()),
        }
    }
}
fn unavailable() -> String {
    "JWKS admission database unavailable or invalid".into()
}
async fn clock(conn: &mut PgConnection) -> Result<i64, String> {
    sqlx::query_scalar("SELECT floor(extract(epoch from clock_timestamp())*1000000)::bigint")
        .fetch_one(conn)
        .await
        .map_err(|_| unavailable())
}
fn micros(seconds: u64) -> Result<i64, String> {
    i64::try_from(seconds)
        .ok()
        .and_then(|v| v.checked_mul(1_000_000))
        .filter(|v| *v > 0)
        .ok_or_else(unavailable)
}
fn horizon(now: i64, delta: i64) -> Result<i64, String> {
    now.checked_add(delta)
        .filter(|v| *v > now)
        .ok_or_else(unavailable)
}
fn failure(row: &mut Row, now: i64, threshold: u32, reset: i64) -> Result<(), String> {
    row.failures = row.failures.saturating_add(1).min(i64::from(u32::MAX));
    if row.open_until.is_some() || row.failures >= i64::from(threshold) {
        row.open_until = Some(horizon(now, reset)?);
    }
    row.owner = None;
    row.lease_until = None;
    Ok(())
}
async fn save(
    conn: &mut PgConnection,
    namespace: &str,
    uri: &[u8; 32],
    row: &Row,
) -> Result<(), String> {
    let count=sqlx::query("UPDATE aegaeon.runtime_jwks_fetches SET failures=$3,open_until_us=$4,owner=$5,lease_until_us=$6,expires_us=$7 WHERE namespace=$1 AND uri_digest=$2")
        .bind(namespace).bind(uri.as_slice()).bind(row.failures).bind(row.open_until).bind(row.owner).bind(row.lease_until).bind(row.expires).execute(conn).await.map_err(|_|unavailable())?.rows_affected();
    if count != 1 {
        return Err(unavailable());
    }
    Ok(())
}

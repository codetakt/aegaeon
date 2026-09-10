//! Bounded storage for short-lived authorization continuations.
//!
//! Counts and insertion share an environment lock and transaction. Completed
//! rows remain in the window so consumption cannot refund the insertion budget.
use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

const CAPACITY: i64 = 4096;
const PER_MINUTE: i64 = 300;
const CLEANUP_BATCH: i64 = 512;
const MAX_URI_BYTES: usize = 32_768;
const MAX_SNAPSHOT_BYTES: usize = 65_536;

#[derive(Clone, Copy)]
pub(super) enum Kind {
    Login,
    Consent,
}

impl Kind {
    fn table(self) -> &'static str {
        match self {
            Self::Login => "aegaeon.authorization_logins",
            Self::Consent => "aegaeon.authorization_consents",
        }
    }
}

fn error(status: StatusCode, code: &str, description: &str) -> Response {
    let mut response = (
        status,
        Json(serde_json::json!({
            "error": code, "error_description": description,
        })),
    )
        .into_response();
    crate::util::apply_no_cache_headers(&mut response);
    if status == StatusCode::TOO_MANY_REQUESTS {
        response.headers_mut().insert(
            header::RETRY_AFTER,
            axum::http::HeaderValue::from_static("60"),
        );
    }
    response
}

fn unavailable() -> Response {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "authorization transaction storage is unavailable",
    )
}

async fn prune(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    kind: Kind,
) -> Result<u64, sqlx::Error> {
    // The table identifier is an enum constant, never request data. SKIP LOCKED
    // lets cleanup yield to a transaction that is completing a live request.
    let sql = format!(
        "DELETE FROM {table} WHERE id IN (
        SELECT id FROM {table} WHERE environment_id=$1 AND expires_at<=statement_timestamp()
        ORDER BY expires_at,id LIMIT $2 FOR UPDATE SKIP LOCKED)",
        table = kind.table()
    );
    Ok(sqlx::query(&sql)
        .bind(environment)
        .bind(CLEANUP_BATCH)
        .execute(&mut **tx)
        .await?
        .rows_affected())
}

pub(super) async fn begin(
    pool: &PgPool,
    environment: Uuid,
    kind: Kind,
    uri: &str,
    snapshot: &Value,
) -> Result<Transaction<'static, Postgres>, Response> {
    if uri.len() > MAX_URI_BYTES
        || serde_json::to_vec(snapshot)
            .map_err(|_| unavailable())?
            .len()
            > MAX_SNAPSHOT_BYTES
    {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "authorization transaction exceeds the storage size limit",
        ));
    }
    let mut tx = pool.begin().await.map_err(|_| unavailable())?;
    // Counts must observe commits made before this admission acquired the lock,
    // even when the database/pool default would retain an earlier snapshot.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *tx)
        .await
        .map_err(|_| unavailable())?;
    sqlx::query("SET LOCAL statement_timeout='2s'")
        .execute(&mut *tx)
        .await
        .map_err(|_| unavailable())?;
    let locked: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM aegaeon.environments WHERE id=$1 FOR UPDATE NOWAIT")
            .bind(environment)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| unavailable())?;
    if locked.is_none() {
        return Err(unavailable());
    }
    prune(&mut tx, environment, kind)
        .await
        .map_err(|_| unavailable())?;
    let sql = format!("SELECT count(*),count(*) FILTER (WHERE created_at>statement_timestamp()-interval '1 minute')
        FROM (SELECT created_at FROM {} WHERE environment_id=$1 LIMIT $2) bounded_rows", kind.table());
    let (retained, recent): (i64, i64) = sqlx::query_as(&sql)
        .bind(environment)
        .bind(CAPACITY)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| unavailable())?;
    if retained >= CAPACITY || recent >= PER_MINUTE {
        // Keep bounded expiry work even when no insertion is admitted.
        tx.commit().await.map_err(|_| unavailable())?;
        return Err(error(
            StatusCode::TOO_MANY_REQUESTS,
            "temporarily_unavailable",
            "authorization transaction limit reached; retry later",
        ));
    }
    Ok(tx)
}

/// Remove bounded batches of expired login and consent records for one issuer environment.
///
/// # Errors
/// Returns a database error; live records remain protected by the expiry predicate.
pub async fn cleanup_expired_authorization_transactions(
    pool: &PgPool,
    environment: Uuid,
) -> Result<u64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL statement_timeout='2s'")
        .execute(&mut *tx)
        .await?;
    let mut removed = 0;
    for kind in [Kind::Login, Kind::Consent] {
        removed += prune(&mut tx, environment, kind).await?;
    }
    tx.commit().await?;
    Ok(removed)
}

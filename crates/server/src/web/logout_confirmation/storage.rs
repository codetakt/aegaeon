use super::{invalid, unavailable, Browser};
use crate::web::{
    authorization_transactions::{self, Kind},
    logout_context::LogoutQuery,
    AppState,
};
use axum::response::Response;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;

pub(super) fn digest(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(aegaeon_crypto::hash::sha256_digest(value.as_bytes()))
}

fn random_secret() -> Result<String, Response> {
    let mut bytes = [0u8; 32];
    aegaeon_crypto::rand::fill_random(&mut bytes).map_err(|_| unavailable("entropy"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub(super) struct Pending {
    id: Uuid,
    snapshot: Value,
    pub(super) query: LogoutQuery,
}

pub(super) async fn create(
    state: &AppState,
    query: &LogoutQuery,
) -> Result<(String, String), Response> {
    let snapshot = serde_json::to_value(query).map_err(|_| unavailable("snapshot"))?;
    let token = random_secret()?;
    let browser = random_secret()?;
    let mut tx = authorization_transactions::begin_with_limits(
        &state.db_pool,
        state.environment_id,
        Kind::Logout,
        "",
        &snapshot,
        &state.cfg.database.authorization_admission,
    )
    .await?;
    sqlx::query(
        "INSERT INTO aegaeon.logout_confirmations
        (environment_id,issuer,token_sha256,browser_sha256,request_snapshot,expires_at)
        VALUES ($1,$2,$3,$4,$5,statement_timestamp()+interval '5 minutes')",
    )
    .bind(state.environment_id)
    .bind(state.issuer.as_str())
    .bind(digest(&token))
    .bind(digest(&browser))
    .bind(snapshot)
    .execute(&mut *tx)
    .await
    .map_err(|_| unavailable("transaction_insert"))?;
    tx.commit()
        .await
        .map_err(|_| unavailable("transaction_commit"))?;
    Ok((token, browser))
}

pub(super) async fn load(state: &AppState, token: &str, secret: &str) -> Result<Pending, Response> {
    let row = sqlx::query(
        "SELECT id,request_snapshot FROM aegaeon.logout_confirmations
        WHERE environment_id=$1 AND issuer=$2 AND token_sha256=$3 AND browser_sha256=$4
        AND decision IS NULL AND expires_at>statement_timestamp()",
    )
    .bind(state.environment_id)
    .bind(state.issuer.as_str())
    .bind(digest(token))
    .bind(digest(secret))
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|_| unavailable("transaction_load"))?
    .ok_or_else(invalid)?;
    let snapshot: Value = row
        .try_get("request_snapshot")
        .map_err(|_| unavailable("snapshot_load"))?;
    let query =
        serde_json::from_value(snapshot.clone()).map_err(|_| unavailable("snapshot_decode"))?;
    Ok(Pending {
        id: row
            .try_get("id")
            .map_err(|_| unavailable("transaction_id"))?,
        snapshot,
        query,
    })
}

pub(super) async fn present(
    state: &AppState,
    pending: &Pending,
    browser: &Browser,
) -> Result<(), Response> {
    let count = sqlx::query("UPDATE aegaeon.logout_confirmations
        SET presented_at=COALESCE(presented_at,statement_timestamp()), session_sha256=$4,subject=$5
        WHERE id=$1 AND environment_id=$2 AND issuer=$3 AND request_snapshot=$6
        AND decision IS NULL AND expires_at>statement_timestamp()
        AND (presented_at IS NULL OR (session_sha256 IS NOT DISTINCT FROM $4 AND subject IS NOT DISTINCT FROM $5))")
        .bind(pending.id).bind(state.environment_id).bind(state.issuer.as_str())
        .bind(browser.digest()).bind(browser.subject()).bind(&pending.snapshot)
        .execute(&state.db_pool).await.map_err(|_| unavailable("presentation_bind"))?.rows_affected();
    if count != 1 {
        return Err(invalid());
    }
    Ok(())
}

pub(super) async fn consume(
    state: &AppState,
    pending: &Pending,
    browser: &Browser,
    token: &str,
    secret: &str,
    decision: &str,
) -> Result<(), Response> {
    let count = sqlx::query(
        "UPDATE aegaeon.logout_confirmations SET decision=$1,decided_at=statement_timestamp()
        WHERE id=$2 AND environment_id=$3 AND issuer=$4 AND request_snapshot=$5
        AND token_sha256=$6 AND browser_sha256=$7 AND presented_at IS NOT NULL
        AND session_sha256 IS NOT DISTINCT FROM $8 AND subject IS NOT DISTINCT FROM $9
        AND decision IS NULL AND expires_at>statement_timestamp()",
    )
    .bind(decision)
    .bind(pending.id)
    .bind(state.environment_id)
    .bind(state.issuer.as_str())
    .bind(&pending.snapshot)
    .bind(digest(token))
    .bind(digest(secret))
    .bind(browser.digest())
    .bind(browser.subject())
    .execute(&state.db_pool)
    .await
    .map_err(|_| unavailable("decision_consume"))?
    .rows_affected();
    if count != 1 {
        return Err(invalid());
    }
    Ok(())
}

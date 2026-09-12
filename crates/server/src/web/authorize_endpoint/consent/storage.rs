use super::super::session::AuthorizeSessionState;
use crate::web::AppState;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;

fn no_cache_json_error(status: StatusCode, error: &str, description: Option<&str>) -> Response {
    let mut response = (
        status,
        Json(serde_json::json!({"error": error, "error_description": description})),
    )
        .into_response();
    crate::util::apply_no_cache_headers(&mut response);
    response
}

pub(super) fn unavailable() -> Response {
    tracing::error!(
        reason = "consent_storage_unavailable",
        "consent request could not be processed"
    );
    no_cache_json_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        Some("consent storage is unavailable"),
    )
}

pub(super) fn invalid() -> Response {
    rejected("consent_request_invalid")
}

pub(super) fn rejected(reason: &'static str) -> Response {
    tracing::warn!(reason, "consent request rejected");
    no_cache_json_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        Some("consent request could not be validated; restart authorization"),
    )
}

fn digest(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(aegaeon_crypto::hash::sha256_digest(value.as_bytes()))
}

pub(super) struct Pending {
    pub(super) id: Uuid,
    pub(super) uri: String,
    pub(super) snapshot: Value,
}

pub(super) async fn create(
    state: &AppState,
    session: &AuthorizeSessionState,
    uri: &str,
    snapshot: &Value,
) -> Result<String, Response> {
    let sid = session.session_id.as_deref().ok_or_else(invalid)?;
    let mut entropy = [0u8; 32];
    aegaeon_crypto::rand::fill_random(&mut entropy).map_err(|_| unavailable())?;
    let token = URL_SAFE_NO_PAD.encode(entropy);
    let mut tx = crate::web::authorization_transactions::begin_with_limits(
        &state.db_pool,
        state.environment_id,
        crate::web::authorization_transactions::Kind::Consent,
        uri,
        snapshot,
        &state.cfg.database.authorization_admission,
    )
    .await?;
    sqlx::query("INSERT INTO aegaeon.authorization_consents
        (environment_id,issuer,subject,session_sha256,token_sha256,authorize_uri,request_snapshot,created_at,expires_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,statement_timestamp(),statement_timestamp()+interval '5 minutes')")
        .bind(state.environment_id).bind(state.issuer.as_str()).bind(&session.user_id)
        .bind(digest(sid)).bind(digest(&token)).bind(uri).bind(snapshot)
        .execute(&mut *tx).await.map_err(|err| {
            tracing::error!(error=%err,"consent transaction could not be stored"); unavailable()
        })?;
    tx.commit().await.map_err(|_| unavailable())?;
    Ok(token)
}

pub(super) async fn load(
    state: &AppState,
    sid: &str,
    subject: &str,
    token: &str,
) -> Result<Pending, Response> {
    let row = sqlx::query(
        "SELECT id,authorize_uri,request_snapshot FROM aegaeon.authorization_consents
        WHERE environment_id=$1 AND issuer=$2 AND subject=$3 AND session_sha256=$4
        AND token_sha256=$5 AND decision IS NULL AND expires_at > now()",
    )
    .bind(state.environment_id)
    .bind(state.issuer.as_str())
    .bind(subject)
    .bind(digest(sid))
    .bind(digest(token))
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|_| unavailable())?
    .ok_or_else(|| rejected("consent_transaction_binding_or_lifetime"))?;
    Ok(Pending {
        id: row.try_get("id").map_err(|_| unavailable())?,
        uri: row.try_get("authorize_uri").map_err(|_| unavailable())?,
        snapshot: row.try_get("request_snapshot").map_err(|_| unavailable())?,
    })
}

pub(super) async fn decide(
    state: &AppState,
    session: &AuthorizeSessionState,
    pending: &Pending,
    decision: &str,
) -> Result<(), Response> {
    let sid = session.session_id.as_deref().ok_or_else(invalid)?;
    let count = sqlx::query(
        "UPDATE aegaeon.authorization_consents SET decision=$1,decided_at=now()
        WHERE id=$2 AND environment_id=$3 AND issuer=$4 AND subject=$5 AND session_sha256=$6
        AND request_snapshot=$7 AND decision IS NULL AND expires_at > now()",
    )
    .bind(decision)
    .bind(pending.id)
    .bind(state.environment_id)
    .bind(state.issuer.as_str())
    .bind(&session.user_id)
    .bind(digest(sid))
    .bind(&pending.snapshot)
    .execute(&state.db_pool)
    .await
    .map_err(|_| unavailable())?
    .rows_affected();
    if count != 1 {
        return Err(rejected("consent_changed_before_decision"));
    }
    Ok(())
}

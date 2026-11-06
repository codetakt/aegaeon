use super::{
    auth_store::StoredUpstreamAuthRequest,
    store::{upstream_auth_request_is_fresh_at, valid_browser_binding_digest},
    UpstreamAuthRequest,
};
use crate::dcr_persistence::admitted_connection::AdmittedConnection;
use sqlx::PgPool;
use std::time::{Duration, SystemTime};

#[derive(Clone)]
pub(super) struct PostgresUpstreamAuthStore {
    pool: PgPool,
    namespace: String,
}

fn unavailable() -> String {
    "upstream authorization database unavailable".into()
}
fn codec_error() -> String {
    "invalid upstream authorization snapshot".into()
}

// SQL stores microseconds; truncation can only shorten the acceptance horizon.
// Avoid floating-point epoch conversion and reject out-of-range representations.
fn database_expiry(value: SystemTime) -> Result<String, String> {
    let nanos = i128::try_from(
        value
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| codec_error())?
            .as_nanos(),
    )
    .map_err(|_| codec_error())?;
    let value =
        time::OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|_| codec_error())?;
    Ok(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06}+00",
        value.year(),
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute(),
        value.second(),
        value.microsecond()
    ))
}

impl PostgresUpstreamAuthStore {
    pub(super) fn new(pool: PgPool, namespace: String) -> Self {
        Self { pool, namespace }
    }

    pub(super) async fn insert(&self, request: &UpstreamAuthRequest) -> Result<(), String> {
        if !upstream_auth_request_is_fresh_at(request, SystemTime::now()) {
            return Err("expired upstream authorization".into());
        }
        let dto = StoredUpstreamAuthRequest::from_request(request).map_err(|_| codec_error())?;
        let payload = serde_json::to_string(&dto).map_err(|_| codec_error())?;
        let expiry = database_expiry(request.expires_at)?;
        let digest = aegaeon_crypto::hash::sha256_digest(request.state.as_bytes());
        let mut connection = AdmittedConnection::acquire(&self.pool)
            .await
            .map_err(|_| unavailable())?;
        let result=tokio::time::timeout(Duration::from_secs(5),async {
            crate::organizations::request_work::async_store::admit_current_commit().map_err(|_| unavailable())?;
            let count=sqlx::query("INSERT INTO aegaeon.runtime_upstream_auth(namespace,token_digest,payload,expires_at) VALUES($1,$2,$3,$4::text::timestamptz) ON CONFLICT DO NOTHING")
                .bind(&self.namespace).bind(digest.as_slice()).bind(payload).bind(expiry)
                .execute(connection.as_mut().map_err(|_| unavailable())?).await.map_err(|_| unavailable())?.rows_affected();
            if count==1 { Ok(()) } else { Err("upstream authorization state already exists".into()) }
        }).await.map_err(|_| unavailable()).and_then(|result| result);
        connection.release().await;
        result
    }

    pub(super) async fn consume(
        &self,
        state: &str,
        browser_digest: &str,
        redirect_uri: &str,
    ) -> Result<Option<UpstreamAuthRequest>, String> {
        if !valid_browser_binding_digest(browser_digest) {
            return Ok(None);
        }
        let digest = aegaeon_crypto::hash::sha256_digest(state.as_bytes());
        let mut connection = AdmittedConnection::acquire(&self.pool)
            .await
            .map_err(|_| unavailable())?;
        let result=tokio::time::timeout(Duration::from_secs(5),async {
            let payload=sqlx::query_scalar::<_,String>("SELECT payload FROM aegaeon.runtime_upstream_auth WHERE namespace=$1 AND token_digest=$2 AND expires_at>statement_timestamp()")
                .bind(&self.namespace).bind(digest.as_slice()).fetch_optional(connection.as_mut().map_err(|_| unavailable())?).await.map_err(|_| unavailable())?;
            let Some(payload)=payload else { return Ok(None); };
            let request=serde_json::from_str::<StoredUpstreamAuthRequest>(&payload).map_err(|_| codec_error())?.into_request().map_err(|_| codec_error())?;
            if request.state!=state || request.redirect_uri!=redirect_uri || !upstream_auth_request_is_fresh_at(&request,SystemTime::now())
                || !request.browser_binding_digest.as_deref().is_some_and(|stored| crate::util::constant_time_eq(stored.as_bytes(),browser_digest.as_bytes())) { return Ok(None); }
            crate::organizations::request_work::async_store::admit_current_commit().map_err(|_| unavailable())?;
            let live=sqlx::query_scalar::<_,bool>("DELETE FROM aegaeon.runtime_upstream_auth WHERE namespace=$1 AND token_digest=$2 AND payload=$3 RETURNING expires_at>clock_timestamp()")
                .bind(&self.namespace).bind(digest.as_slice()).bind(payload)
                .fetch_optional(connection.as_mut().map_err(|_| unavailable())?).await.map_err(|_| unavailable())?;
            Ok(if live==Some(true) && upstream_auth_request_is_fresh_at(&request,SystemTime::now()) { Some(request) } else { None })
        }).await.map_err(|_| unavailable()).and_then(|result| result);
        connection.release().await;
        result.map(|request| {
            request.filter(|request| upstream_auth_request_is_fresh_at(request, SystemTime::now()))
        })
    }

    pub(super) async fn cleanup(&self) -> Result<(), String> {
        crate::runtime_security_cleanup::cleanup(
            &self.pool,
            &self.namespace,
            crate::runtime_security_cleanup::Kind::UpstreamAuth,
            crate::runtime_security_cleanup::PASS_BATCHES,
        )
        .await
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests;

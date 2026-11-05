use super::{redis_state::StoredAuthSession, AuthSession};
use crate::dcr_persistence::admitted_connection::AdmittedConnection;
use aegaeon_crypto::hash::sha256_digest;
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};

mod envelope;
mod inventory;
mod reads;
#[cfg(test)]
mod tests;

#[derive(Clone)]
pub(super) struct PostgresAuthSessions {
    pool: PgPool,
    namespace: String,
    key: Arc<[u8; 32]>,
}

fn unavailable() -> String {
    "browser session database unavailable".into()
}

impl PostgresAuthSessions {
    pub(super) fn new(pool: PgPool, namespace: String, key: [u8; 32]) -> Self {
        Self {
            pool,
            namespace,
            key: Arc::new(key),
        }
    }

    pub(super) async fn create(
        &self,
        sid: &str,
        session: &AuthSession,
        capacity: usize,
    ) -> Result<(), String> {
        let now = super::now_epoch_secs()?;
        if session.auth_time_epoch_secs > session.created_at_epoch_secs
            || session.created_at_epoch_secs > now
            || session.expires_at_epoch_secs <= now
        {
            return Err("invalid browser session time bounds".into());
        }
        let expiry = i64::try_from(session.expires_at_epoch_secs).map_err(|_| unavailable())?;
        let expiry = time::OffsetDateTime::from_unix_timestamp(expiry)
            .map_err(|_| unavailable())?
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| unavailable())?;
        let created = i64::try_from(session.created_at_epoch_secs).map_err(|_| unavailable())?;
        let capacity = i32::try_from(capacity).map_err(|_| unavailable())?;
        let digest = sha256_digest(sid.as_bytes());
        let subject = sha256_digest(session.user_id.as_bytes());
        let sealed = envelope::seal(&self.key, &self.namespace, sid)?;
        let payload = serde_json::to_string(&StoredAuthSession::from_session(session))
            .map_err(|_| unavailable())?;
        if payload.len() > 65536 {
            return Err("browser session payload exceeds byte bound".into());
        }
        let mut connection = AdmittedConnection::acquire(&self.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            crate::organizations::request_work::async_store::admit_current_commit().map_err(|_| unavailable())?;
            sqlx::query("SELECT aegaeon.create_runtime_browser_session($1,$2,$3,$4,$5,$6,$7::text::timestamptz,$8)")
                .bind(&self.namespace).bind(digest.as_slice()).bind(subject.as_slice()).bind(sealed)
                .bind(payload).bind(created).bind(expiry).bind(capacity)
                .execute(connection.as_mut().map_err(|_| unavailable())?).await.map_err(|_| unavailable())?;
            Ok(())
        }).await.map_err(|_| unavailable()).and_then(|result| result);
        connection.release().await;
        result
    }

    pub(super) async fn delete(
        &self,
        sid: Option<&str>,
        subject: Option<&str>,
    ) -> Result<usize, String> {
        if sid.is_none() && subject.is_none() {
            return Err("missing browser session selector".into());
        }
        let digest = sid.map(|sid| sha256_digest(sid.as_bytes()).to_vec());
        let subject = subject.map(|subject| sha256_digest(subject.as_bytes()).to_vec());
        let mut connection = AdmittedConnection::acquire(&self.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            crate::organizations::request_work::async_store::admit_current_commit()
                .map_err(|_| unavailable())?;
            sqlx::query_scalar::<_, i64>("SELECT aegaeon.delete_runtime_browser_sessions($1,$2,$3)")
                .bind(&self.namespace)
                .bind(digest)
                .bind(subject)
                .fetch_one(connection.as_mut().map_err(|_| unavailable())?)
                .await
                .map_err(|_| unavailable())
                .and_then(|result| usize::try_from(result).map_err(|_| unavailable()))
        })
        .await
        .map_err(|_| unavailable())
        .and_then(|result| result);
        connection.release().await;
        result
    }

    pub(super) async fn cleanup(&self) -> Result<(), String> {
        crate::runtime_security_cleanup::cleanup(
            &self.pool,
            &self.namespace,
            crate::runtime_security_cleanup::Kind::BrowserSession,
            crate::runtime_security_cleanup::PASS_BATCHES,
        )
        .await
        .map(|_| ())
    }
}

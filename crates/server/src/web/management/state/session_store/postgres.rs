use super::ManagementSession;
use crate::dcr_persistence::admitted_connection::AdmittedConnection;
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone)]
pub(in crate::web::management) struct PostgresManagementSessions {
    pool: PgPool,
    namespace: String,
}

fn unavailable() -> String {
    "management session database unavailable".into()
}

impl PostgresManagementSessions {
    pub(super) fn new(pool: PgPool, namespace: String) -> Self {
        Self { pool, namespace }
    }

    pub(super) async fn create(
        &self,
        administrator: Uuid,
        now: u64,
        ttl: u64,
        capacity: usize,
    ) -> Result<Option<String>, String> {
        let Some(expiry) = now
            .checked_add(ttl)
            .and_then(|value| i64::try_from(value).ok())
        else {
            return Ok(None);
        };
        let Ok(created) = i64::try_from(now) else {
            return Ok(None);
        };
        let expiry_text = time::OffsetDateTime::from_unix_timestamp(expiry)
            .map_err(|_| "management session expiry is out of range")?
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| "management session expiry is out of range")?;
        let capacity = i32::try_from(capacity).map_err(|_| unavailable())?;
        let sid = uuid::Builder::from_random_bytes(aegaeon_crypto::rand::random_array())
            .into_uuid()
            .to_string();
        let digest = aegaeon_crypto::hash::sha256_digest(sid.as_bytes());
        let mut connection = AdmittedConnection::acquire(&self.pool)
            .await
            .map_err(|_| unavailable())?;
        let result=tokio::time::timeout(Duration::from_secs(5), async {
            crate::organizations::request_work::async_store::admit_current_commit().map_err(|_| unavailable())?;
            sqlx::query("SELECT aegaeon.create_runtime_management_session($1,$2,$3,$4,$5::text::timestamptz,$6)")
                .bind(&self.namespace).bind(digest.as_slice()).bind(administrator).bind(created).bind(expiry_text).bind(capacity)
                .execute(connection.as_mut().map_err(|_| unavailable())?).await.map_err(|_| unavailable())?;
            Ok(Some(sid))
        }).await.map_err(|_| unavailable()).and_then(|result| result);
        connection.release().await;
        result
    }

    pub(super) async fn get(
        &self,
        sid: &str,
        now: u64,
        ttl: u64,
    ) -> Result<Option<ManagementSession>, String> {
        let mut connection = AdmittedConnection::acquire(&self.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = self
            .read_row(
                connection.as_mut().map_err(|_| unavailable())?,
                sid,
                now,
                ttl,
                false,
            )
            .await;
        connection.release().await;
        decode_session(result?, ttl)
    }

    pub(super) async fn get_admitted(
        &self,
        admission: &crate::organizations::request_work::Admission,
        sid: &str,
        now: u64,
        ttl: u64,
    ) -> Result<Option<ManagementSession>, String> {
        let mut connection = admission
            .connection(&self.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = self
            .read_row(
                connection.as_mut().map_err(|_| unavailable())?,
                sid,
                now,
                ttl,
                false,
            )
            .await;
        connection.release().await;
        admission.ensure_open().map_err(|_| unavailable())?;
        decode_session(result?, ttl)
    }

    pub(super) async fn get_in_transaction(
        &self,
        connection: &mut sqlx::PgConnection,
        sid: &str,
        now: u64,
        ttl: u64,
    ) -> Result<Option<ManagementSession>, String> {
        decode_session(self.read_row(connection, sid, now, ttl, true).await?, ttl)
    }

    async fn read_row(
        &self,
        connection: &mut sqlx::PgConnection,
        sid: &str,
        now: u64,
        ttl: u64,
        lock: bool,
    ) -> Result<Option<(Uuid, i64, i64)>, String> {
        let Ok(now) = i64::try_from(now) else {
            return Ok(None);
        };
        let ttl = i64::try_from(ttl).map_err(|_| unavailable())?;
        let digest = aegaeon_crypto::hash::sha256_digest(sid.as_bytes());
        let query="SELECT administrator_id,created_at_epoch_secs,extract(epoch from expires_at)::bigint FROM aegaeon.runtime_management_sessions WHERE namespace=$1 AND token_digest=$2 AND created_at_epoch_secs<=$3 AND $3-created_at_epoch_secs<$4 AND expires_at>statement_timestamp()";
        // A final check in the caller's transaction holds the current session
        // against deletion/eviction until that transaction finishes.
        let query = if lock {
            format!("{query} FOR SHARE")
        } else {
            query.to_owned()
        };
        tokio::time::timeout(
            Duration::from_secs(5),
            sqlx::query_as::<_, (Uuid, i64, i64)>(&query)
                .bind(&self.namespace)
                .bind(digest.as_slice())
                .bind(now)
                .bind(ttl)
                .fetch_optional(connection),
        )
        .await
        .map_err(|_| unavailable())
        .and_then(|result| result.map_err(|_| unavailable()))
    }

    pub(super) async fn delete(&self, sid: &str) -> Result<bool, String> {
        let digest = aegaeon_crypto::hash::sha256_digest(sid.as_bytes());
        let mut connection = AdmittedConnection::acquire(&self.pool)
            .await
            .map_err(|_| unavailable())?;
        let result=tokio::time::timeout(Duration::from_secs(5),async {
            crate::organizations::request_work::async_store::admit_current_commit().map_err(|_| unavailable())?;
            sqlx::query("DELETE FROM aegaeon.runtime_management_sessions WHERE namespace=$1 AND token_digest=$2")
                .bind(&self.namespace).bind(digest.as_slice()).execute(connection.as_mut().map_err(|_| unavailable())?).await
                .map(|result| result.rows_affected()==1).map_err(|_| unavailable())
        }).await.map_err(|_| unavailable()).and_then(|result| result);
        connection.release().await;
        result
    }

    pub(super) async fn cleanup(&self) -> Result<(), String> {
        crate::runtime_security_cleanup::cleanup(
            &self.pool,
            &self.namespace,
            crate::runtime_security_cleanup::Kind::ManagementSession,
            crate::runtime_security_cleanup::PASS_BATCHES,
        )
        .await
        .map(|_| ())
    }
}

fn decode_session(
    row: Option<(Uuid, i64, i64)>,
    ttl: u64,
) -> Result<Option<ManagementSession>, String> {
    let Some((administrator, created, expiry)) = row else {
        return Ok(None);
    };
    let created = u64::try_from(created).map_err(|_| unavailable())?;
    let current = crate::util::now_unix_epoch_secs().map_err(|_| unavailable())?;
    if current >= u64::try_from(expiry).map_err(|_| unavailable())?
        || current.checked_sub(created).is_none_or(|age| age >= ttl)
    {
        return Ok(None);
    }
    Ok(Some(ManagementSession::human(administrator, created)))
}

#[cfg(test)]
mod tests;

use super::*;

// The current inventory API returns one vector. Refuse oversized inventories
// explicitly rather than silently truncating them or allocating without a bound.
#[cfg(test)]
const INVENTORY_LIMIT: i64 = 4096;

pub(super) struct Row {
    pub(super) token_digest: Vec<u8>,
    subject_digest: Vec<u8>,
    session_envelope: Vec<u8>,
    pub(super) payload: String,
    created_at_epoch_secs: i64,
    expiry: i64,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for Row {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row as _;
        Ok(Self {
            token_digest: row.try_get("token_digest")?,
            subject_digest: row.try_get("subject_digest")?,
            session_envelope: row.try_get("session_envelope")?,
            payload: row.try_get("payload")?,
            created_at_epoch_secs: row.try_get("created_at_epoch_secs")?,
            expiry: row.try_get("expiry")?,
        })
    }
}

impl PostgresAuthSessions {
    pub(in crate::web::auth_session) async fn get(
        &self,
        sid: &str,
    ) -> Result<Option<AuthSession>, String> {
        let digest = sha256_digest(sid.as_bytes());
        let mut connection = AdmittedConnection::acquire(&self.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5),
            sqlx::query_as::<_, Row>("SELECT token_digest,subject_digest,session_envelope,payload,created_at_epoch_secs,extract(epoch from expires_at)::bigint AS expiry FROM aegaeon.runtime_browser_sessions WHERE namespace=$1 AND token_digest=$2 AND expires_at>statement_timestamp()")
                .bind(&self.namespace).bind(digest.as_slice()).fetch_optional(connection.as_mut().map_err(|_| unavailable())?)
        ).await.map_err(|_| unavailable()).and_then(|result| result.map_err(|_| unavailable()));
        connection.release().await;
        result?
            .map(|row| self.decode(&row))
            .transpose()
            .map(|value| value.flatten().map(|(_, session)| session))
    }

    #[cfg(test)]
    pub(in crate::web::auth_session) async fn list(
        &self,
        subject: &str,
    ) -> Result<Vec<(String, AuthSession)>, String> {
        let digest = sha256_digest(subject.as_bytes());
        let mut connection = AdmittedConnection::acquire(&self.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5),
            sqlx::query_as::<_, Row>("SELECT token_digest,subject_digest,session_envelope,payload,created_at_epoch_secs,extract(epoch from expires_at)::bigint AS expiry FROM aegaeon.runtime_browser_sessions WHERE namespace=$1 AND subject_digest=$2 AND expires_at>statement_timestamp() ORDER BY expires_at,token_digest LIMIT $3")
                .bind(&self.namespace).bind(digest.as_slice()).bind(INVENTORY_LIMIT+1)
                .fetch_all(connection.as_mut().map_err(|_| unavailable())?)
        ).await.map_err(|_| unavailable()).and_then(|result| result.map_err(|_| unavailable()));
        connection.release().await;
        let rows = result?;
        if rows.len() > usize::try_from(INVENTORY_LIMIT).map_err(|_| unavailable())? {
            return Err("browser session inventory exceeds result bound".into());
        }
        rows.into_iter()
            .filter_map(|row| self.decode(&row).transpose())
            .collect()
    }

    pub(super) fn decode(&self, row: &Row) -> Result<Option<(String, AuthSession)>, String> {
        let stored: StoredAuthSession =
            serde_json::from_str(&row.payload).map_err(|_| unavailable())?;
        let session = stored.to_session().ok_or_else(unavailable)?;
        if session.created_at_epoch_secs
            != u64::try_from(row.created_at_epoch_secs).map_err(|_| unavailable())?
            || session.expires_at_epoch_secs
                != u64::try_from(row.expiry).map_err(|_| unavailable())?
            || !crate::util::constant_time_eq(
                &sha256_digest(session.user_id.as_bytes()),
                &row.subject_digest,
            )
            || session.auth_time_epoch_secs > session.created_at_epoch_secs
            || session.expires_at_epoch_secs <= session.created_at_epoch_secs
        {
            return Err("invalid browser session binding".into());
        }
        let sid = envelope::open(
            &self.key,
            &self.namespace,
            &row.token_digest,
            &row.session_envelope,
        )?;
        let now = super::super::now_epoch_secs()?;
        if session.created_at_epoch_secs > now || session.expires_at_epoch_secs <= now {
            return Ok(None);
        }
        Ok(Some((sid, session)))
    }
}

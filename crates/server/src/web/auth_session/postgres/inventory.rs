use super::{reads::Row, *};
use crate::web::auth_session::inventory::{SessionCursor, SessionPage};

impl PostgresAuthSessions {
    pub(in crate::web::auth_session) async fn find(
        &self,
        subject: &str,
        digest: &[u8; 32],
    ) -> Result<Option<String>, String> {
        let subject = sha256_digest(subject.as_bytes());
        let mut connection = AdmittedConnection::acquire(&self.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5),
            sqlx::query_as::<_, Row>("SELECT token_digest,subject_digest,session_envelope,payload,created_at_epoch_secs,extract(epoch from expires_at)::bigint AS expiry FROM aegaeon.runtime_browser_sessions WHERE namespace=$1 AND token_digest=$2 AND subject_digest=$3 AND expires_at>statement_timestamp()")
                .bind(&self.namespace).bind(digest.as_slice()).bind(subject.as_slice()).fetch_optional(connection.as_mut().map_err(|_| unavailable())?)
        ).await.map_err(|_| unavailable()).and_then(|result| result.map_err(|_| unavailable()));
        connection.release().await;
        result?
            .map(|row| self.decode(&row))
            .transpose()
            .map(|value| value.flatten().map(|(sid, _)| sid))
    }

    pub(in crate::web::auth_session) async fn page(
        &self,
        subject: &str,
        cursor: Option<&SessionCursor>,
        limit: usize,
    ) -> Result<SessionPage, String> {
        if !(1..=200).contains(&limit) {
            return Err("invalid browser inventory limit".into());
        }
        let cursor = cursor.cloned().unwrap_or(SessionCursor {
            auth_time: i64::MAX,
            digest: [0; 32],
        });
        let ordering_time = cursor
            .auth_time
            .checked_neg()
            .filter(|_| cursor.auth_time >= 0)
            .ok_or_else(unavailable)?;
        let subject = sha256_digest(subject.as_bytes());
        let mut connection = AdmittedConnection::acquire(&self.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5),
            sqlx::query_as::<_, Row>("SELECT token_digest,subject_digest,session_envelope,payload,created_at_epoch_secs,extract(epoch from expires_at)::bigint AS expiry FROM aegaeon.runtime_browser_sessions WHERE namespace=$1 AND subject_digest=$2 AND (-((payload::jsonb->>'auth_time_epoch_secs')::bigint),token_digest)>($3,$4) AND expires_at>statement_timestamp() ORDER BY -((payload::jsonb->>'auth_time_epoch_secs')::bigint),token_digest LIMIT $5")
                .bind(&self.namespace).bind(subject.as_slice()).bind(ordering_time).bind(cursor.digest.as_slice()).bind(i64::try_from(limit+1).map_err(|_| unavailable())?)
                .fetch_all(connection.as_mut().map_err(|_| unavailable())?)
        ).await.map_err(|_| unavailable()).and_then(|result| result.map_err(|_| unavailable()));
        connection.release().await;
        let rows = result?;
        let next = if rows.len() > limit {
            let row = &rows[limit - 1];
            let stored: StoredAuthSession =
                serde_json::from_str(&row.payload).map_err(|_| unavailable())?;
            Some(SessionCursor {
                auth_time: i64::try_from(stored.auth_time_epoch_secs).map_err(|_| unavailable())?,
                digest: row
                    .token_digest
                    .as_slice()
                    .try_into()
                    .map_err(|_| unavailable())?,
            })
        } else {
            None
        };
        let sessions = rows
            .iter()
            .take(limit)
            .filter_map(|row| self.decode(row).transpose())
            .collect::<Result<_, _>>()?;
        Ok(SessionPage { sessions, next })
    }
}

use super::StepUpChallenge;
use crate::dcr_persistence::admitted_connection::AdmittedConnection;
use aegaeon_crypto::hash::Sha256Hasher;
use sqlx::PgPool;
use std::time::Duration;

#[derive(Clone)]
pub(super) struct PostgresStepUpStore {
    pool: PgPool,
    namespace: String,
}

fn unavailable() -> String {
    "step-up database unavailable".into()
}

fn binding(client: &str, session: &str, request: &str) -> [u8; 32] {
    let mut digest = Sha256Hasher::new();
    for field in [client, session, request] {
        digest.update(&(field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    digest.finalize()
}

impl PostgresStepUpStore {
    pub(super) fn new(pool: PgPool, namespace: String) -> Self {
        Self { pool, namespace }
    }

    pub(super) async fn issue(&self, challenge: &StepUpChallenge) -> Result<(), String> {
        let digest = binding(
            &challenge.client_id,
            &challenge.session_id,
            &challenge.request_id,
        );
        let issued = i64::try_from(challenge.issued_at_epoch_secs).map_err(|_| unavailable())?;
        let expiry = i64::try_from(challenge.expires_at_epoch_secs).map_err(|_| unavailable())?;
        let expiry_text = time::OffsetDateTime::from_unix_timestamp(expiry)
            .map_err(|_| "step-up expiry is out of range")?
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| "step-up expiry is out of range")?;
        let id = uuid::Uuid::parse_str(&challenge.id).map_err(|_| unavailable())?;
        let mut connection = AdmittedConnection::acquire(&self.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            crate::organizations::request_work::async_store::admit_current_commit().map_err(|_| unavailable())?;
            sqlx::query("INSERT INTO aegaeon.runtime_stepup_challenges(namespace,request_digest,challenge_id,issued_at_epoch_secs,expires_at_epoch_secs,expires_at,completed) VALUES($1,$2,$3,$4,$5,$6::text::timestamptz,false) ON CONFLICT(namespace,request_digest) DO UPDATE SET challenge_id=EXCLUDED.challenge_id,issued_at_epoch_secs=EXCLUDED.issued_at_epoch_secs,expires_at_epoch_secs=EXCLUDED.expires_at_epoch_secs,expires_at=EXCLUDED.expires_at,completed=false")
                .bind(&self.namespace).bind(digest.as_slice()).bind(id).bind(issued).bind(expiry).bind(expiry_text)
                .execute(connection.as_mut().map_err(|_| unavailable())?).await.map(|_| ()).map_err(|_| unavailable())
        }).await.map_err(|_| unavailable()).and_then(|result| result);
        connection.release().await;
        result
    }

    pub(super) async fn complete(
        &self,
        client: &str,
        session: &str,
        request: &str,
        now: u64,
    ) -> Result<Option<StepUpChallenge>, String> {
        let Ok(now) = i64::try_from(now) else {
            return Ok(None);
        };
        let digest = binding(client, session, request);
        let mut connection = AdmittedConnection::acquire(&self.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            crate::organizations::request_work::async_store::admit_current_commit().map_err(|_| unavailable())?;
            sqlx::query_as::<_,(uuid::Uuid,i64,i64,bool)>("UPDATE aegaeon.runtime_stepup_challenges SET completed=true WHERE namespace=$1 AND request_digest=$2 AND NOT completed AND issued_at_epoch_secs<=$3 AND expires_at_epoch_secs>$3 RETURNING challenge_id,issued_at_epoch_secs,expires_at_epoch_secs,expires_at>clock_timestamp()")
                .bind(&self.namespace).bind(digest.as_slice()).bind(now)
                .fetch_optional(connection.as_mut().map_err(|_| unavailable())?).await.map_err(|_| unavailable())
        }).await.map_err(|_| unavailable()).and_then(|result| result);
        connection.release().await;
        let Some((id, issued, expiry, live)) = result? else {
            return Ok(None);
        };
        let issued = u64::try_from(issued).map_err(|_| unavailable())?;
        let expiry = u64::try_from(expiry).map_err(|_| unavailable())?;
        if !live || super::now_epoch_secs()? >= expiry {
            return Ok(None);
        }
        Ok(Some(StepUpChallenge {
            id: id.to_string(),
            client_id: client.into(),
            session_id: session.into(),
            request_id: request.into(),
            issued_at_epoch_secs: issued,
            expires_at_epoch_secs: expiry,
            completed: true,
        }))
    }

    pub(super) async fn consume(
        &self,
        client: &str,
        session: &str,
        request: &str,
        now: u64,
    ) -> Result<bool, String> {
        let Ok(now) = i64::try_from(now) else {
            return Ok(false);
        };
        let digest = binding(client, session, request);
        let mut connection = AdmittedConnection::acquire(&self.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            crate::organizations::request_work::async_store::admit_current_commit().map_err(|_| unavailable())?;
            sqlx::query_as::<_,(bool,i64)>("DELETE FROM aegaeon.runtime_stepup_challenges WHERE namespace=$1 AND request_digest=$2 AND completed RETURNING issued_at_epoch_secs<=$3 AND expires_at_epoch_secs>$3 AND expires_at>clock_timestamp(),expires_at_epoch_secs")
                .bind(&self.namespace).bind(digest.as_slice()).bind(now)
                .fetch_optional(connection.as_mut().map_err(|_| unavailable())?).await.map_err(|_| unavailable())
        }).await.map_err(|_| unavailable()).and_then(|result| result);
        connection.release().await;
        let Some((live, expiry)) = result? else {
            return Ok(false);
        };
        Ok(live && super::now_epoch_secs()? < u64::try_from(expiry).map_err(|_| unavailable())?)
    }

    pub(super) async fn cleanup(&self) -> Result<(), String> {
        crate::runtime_security_cleanup::cleanup(
            &self.pool,
            &self.namespace,
            crate::runtime_security_cleanup::Kind::StepUp,
            crate::runtime_security_cleanup::PASS_BATCHES,
        )
        .await
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests;

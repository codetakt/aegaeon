use super::*;
use uuid::Uuid;

impl PostgresTokenStoreBackend {
    // Existing subjects take only a shared row lock, held until publication ends.
    // Revoke-all takes the exclusive lock and replaces this current generation.
    pub(super) async fn lock_subject(
        &self,
        connection: &mut PgConnection,
        digest: &[u8],
        create: bool,
    ) -> Result<Option<Uuid>, String> {
        let query="SELECT generation FROM aegaeon.runtime_token_subjects WHERE namespace=$1 AND subject_digest=$2 FOR SHARE";
        let current = sqlx::query_scalar(query)
            .bind(self.database.namespace.as_ref())
            .bind(digest)
            .fetch_optional(&mut *connection)
            .await
            .map_err(|_| unavailable())?;
        if current.is_some() || !create {
            return Ok(current);
        }
        let generation =
            uuid::Builder::from_random_bytes(aegaeon_crypto::rand::random_array()).into_uuid();
        sqlx::query("INSERT INTO aegaeon.runtime_token_subjects(namespace,subject_digest,generation) VALUES($1,$2,$3) ON CONFLICT DO NOTHING")
            .bind(self.database.namespace.as_ref()).bind(digest).bind(generation).execute(&mut *connection).await.map_err(|_|unavailable())?;
        sqlx::query_scalar(query)
            .bind(self.database.namespace.as_ref())
            .bind(digest)
            .fetch_optional(connection)
            .await
            .map_err(|_| unavailable())
    }

    pub(in crate::authcode::store) async fn revoke_subject(
        &self,
        subject: &str,
    ) -> Result<usize, String> {
        let digest = sha256_digest(subject.as_bytes());
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result=tokio::time::timeout(Duration::from_secs(5),async {
            crate::organizations::request_work::async_store::admit_current_commit().map_err(|_|unavailable())?;
            let mut tx=connection.begin().await.map_err(|_|unavailable())?;
            let generation=sqlx::query_scalar::<_,Uuid>("SELECT generation FROM aegaeon.runtime_token_subjects WHERE namespace=$1 AND subject_digest=$2 FOR UPDATE")
                .bind(self.database.namespace.as_ref()).bind(digest.as_slice()).fetch_optional(&mut *tx).await.map_err(|_|unavailable())?;
            let Some(generation)=generation else {tx.rollback().await.map_err(|_|unavailable())?;return Ok(0);};
            // Exact reporting has a subject-sized read cost, bounded by this SQL deadline.
            let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_token_capabilities WHERE namespace=$1 AND subject_digest=$2 AND subject_generation=$3 AND NOT revoked")
                .bind(self.database.namespace.as_ref()).bind(digest.as_slice()).bind(generation).fetch_one(&mut *tx).await.map_err(|_|unavailable())?;
            let replacement=uuid::Builder::from_random_bytes(aegaeon_crypto::rand::random_array()).into_uuid();
            sqlx::query("UPDATE aegaeon.runtime_token_subjects SET generation=$3 WHERE namespace=$1 AND subject_digest=$2")
                .bind(self.database.namespace.as_ref()).bind(digest.as_slice()).bind(replacement).execute(&mut *tx).await.map_err(|_|unavailable())?;
            tx.commit().await.map_err(|_|unavailable())?;usize::try_from(count).map_err(|_|unavailable())
        }).await.map_err(|_|unavailable()).and_then(|r|r);
        connection.release().await;
        result
    }
}

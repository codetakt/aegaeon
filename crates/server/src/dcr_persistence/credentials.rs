use sqlx::{Postgres, Transaction};
use std::sync::Arc;
use tokio::sync::OwnedSemaphorePermit;
#[cfg(test)]
use tokio::sync::Semaphore;
use uuid::Uuid;

use super::{DcrDatabaseError, DcrStoredClient};

const MAX_ACTIVE_SECRETS: usize = 2;
pub(super) mod admission;

async fn verify_hashes<F>(
    hashes: Vec<(Uuid, String)>,
    assertion: String,
    permit: Arc<OwnedSemaphorePermit>,
    mut verify: F,
) -> Result<(Vec<Uuid>, Arc<OwnedSemaphorePermit>), DcrDatabaseError>
where
    F: FnMut(&str, &str) -> bool + Send + 'static,
{
    if hashes.len() > MAX_ACTIVE_SECRETS {
        return Err(DcrDatabaseError::CorruptRegistration(
            "client secret active capacity exceeded".into(),
        ));
    }
    crate::organizations::request_work::async_store::blocking(move || {
        // A cancelled async caller must not release admission while KDF still runs.
        let matched = hashes
            .into_iter()
            .filter_map(|(id, hash)| verify(&assertion, &hash).then_some(id))
            .collect();
        (matched, permit)
    })
    .await
    .map_err(|_| {
        DcrDatabaseError::CorruptRegistration("client secret verification unavailable".into())
    })
}

// Called only after locking the current registration, client and environment.
// Credential writers share those locks. The database bounds ACTIVE rows to two;
// the third-row sentinel also refuses an unupgraded or corrupted schema before KDF.
pub(super) async fn verify_current_client_secret(
    tx: &mut Transaction<'_, Postgres>,
    stored: &DcrStoredClient,
    assertion: &str,
    permit: Arc<OwnedSemaphorePermit>,
) -> Result<Arc<OwnedSemaphorePermit>, DcrDatabaseError> {
    verify_current_with(
        tx,
        stored,
        assertion,
        permit,
        crate::local_credentials::verify_password,
    )
    .await
}

async fn verify_current_with<F>(
    tx: &mut Transaction<'_, Postgres>,
    stored: &DcrStoredClient,
    assertion: &str,
    permit: Arc<OwnedSemaphorePermit>,
    verify: F,
) -> Result<Arc<OwnedSemaphorePermit>, DcrDatabaseError>
where
    F: FnMut(&str, &str) -> bool + Send + 'static,
{
    let hashes = sqlx::query_as::<_, (Uuid, String)>(
        r"
SELECT id, secret_hash
FROM aegaeon.client_secrets
WHERE environment_id = $1
  AND client_id = $2
  AND status = 'ACTIVE'
  AND secret_hash_algorithm = 'argon2id'
  AND expires_at > statement_timestamp()
LIMIT 3
        ",
    )
    .bind(stored.environment_id)
    .bind(stored.database_client_id)
    .fetch_all(&mut **tx)
    .await?;
    // Check both overlapping credentials, including a valid alternative to an
    // unusable hash. Neither hashes nor assertions enter diagnostics.
    let (matched, permit) = verify_hashes(hashes, assertion.to_owned(), permit, verify).await?;
    // A credential can expire while the blocking worker runs. Sample a fresh
    // statement clock before mutation rather than reusing transaction-start time.
    let current: bool = sqlx::query_scalar(
        r"
SELECT EXISTS (
    SELECT 1 FROM aegaeon.client_secrets
    WHERE environment_id = $1 AND client_id = $2 AND id = ANY($3)
      AND status = 'ACTIVE' AND secret_hash_algorithm = 'argon2id'
      AND expires_at > statement_timestamp()
)
        ",
    )
    .bind(stored.environment_id)
    .bind(stored.database_client_id)
    .bind(&matched)
    .fetch_one(&mut **tx)
    .await?;
    if current {
        Ok(permit)
    } else {
        Err(DcrDatabaseError::ClientSecretMismatch)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod expiry_tests;

#[cfg(test)]
mod organization_epoch;

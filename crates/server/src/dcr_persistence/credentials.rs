use sqlx::{Postgres, Transaction};

use super::{DcrDatabaseError, DcrStoredClient};

// Called only after locking the current registration, client and environment.
// Management credential writers share those locks. A new statement samples the
// database clock after any lock wait, independently of transaction start time.
pub(super) async fn verify_current_client_secret(
    tx: &mut Transaction<'_, Postgres>,
    stored: &DcrStoredClient,
    assertion: &str,
) -> Result<(), DcrDatabaseError> {
    let hashes = sqlx::query_scalar::<_, String>(
        r"
SELECT secret_hash
FROM aegaeon.client_secrets
WHERE environment_id = $1
  AND client_id = $2
  AND status = 'ACTIVE'
  AND secret_hash_algorithm = 'argon2id'
  AND expires_at > statement_timestamp()
        ",
    )
    .bind(stored.environment_id)
    .bind(stored.database_client_id)
    .fetch_all(&mut **tx)
    .await?;
    // Check all eligible overlapping credentials, including valid alternatives
    // to an unusable stored hash. Neither hashes nor assertions enter diagnostics.
    let matched = hashes.iter().fold(false, |matched, hash| {
        crate::local_credentials::verify_password(assertion, hash) | matched
    });
    if matched {
        Ok(())
    } else {
        Err(DcrDatabaseError::ClientSecretMismatch)
    }
}

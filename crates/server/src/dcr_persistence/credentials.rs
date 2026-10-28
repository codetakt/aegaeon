use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use super::{DcrDatabaseError, DcrStoredClient};

const MAX_ACTIVE_SECRETS: usize = 2;

async fn verify_hashes<F>(
    hashes: Vec<(Uuid, String)>,
    assertion: String,
    mut verify: F,
) -> Result<Vec<Uuid>, DcrDatabaseError>
where
    F: FnMut(&str, &str) -> bool + Send + 'static,
{
    if hashes.len() > MAX_ACTIVE_SECRETS {
        return Err(DcrDatabaseError::CorruptRegistration(
            "client secret active capacity exceeded".into(),
        ));
    }
    tokio::task::spawn_blocking(move || {
        hashes
            .into_iter()
            .filter_map(|(id, hash)| verify(&assertion, &hash).then_some(id))
            .collect()
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
) -> Result<(), DcrDatabaseError> {
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
    let matched = verify_hashes(
        hashes,
        assertion.to_owned(),
        crate::local_credentials::verify_password,
    )
    .await?;
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
        Ok(())
    } else {
        Err(DcrDatabaseError::ClientSecretMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[tokio::test(flavor = "current_thread")]
    async fn credential_verification_uses_worker_and_checks_both_overlaps() {
        let executor = std::thread::current().id();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let matched = verify_hashes(
            vec![(first, "first".into()), (second, "second".into())],
            "assertion".into(),
            move |assertion, hash| {
                assert_ne!(std::thread::current().id(), executor);
                assert_eq!(assertion, "assertion");
                observed.fetch_add(1, Ordering::SeqCst);
                hash == "first"
            },
        )
        .await
        .expect("bounded worker");
        assert_eq!(matched, vec![first]);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn credential_overflow_refuses_before_any_hash_work() {
        let hashes = (0..3)
            .map(|_| (Uuid::new_v4(), "private-hash".into()))
            .collect();
        let error = verify_hashes(hashes, "private-assertion".into(), |_, _| {
            panic!("overflow must not reach a verifier")
        })
        .await
        .expect_err("over capacity");
        assert!(matches!(error, DcrDatabaseError::CorruptRegistration(_)));
        assert!(!error.to_string().contains("private"));
    }

    #[tokio::test]
    async fn credential_worker_failure_does_not_admit_or_disclose_input() {
        let error = verify_hashes(
            vec![(Uuid::new_v4(), "hash".into())],
            "assertion".into(),
            |_, _| panic!("injected worker failure"),
        )
        .await
        .expect_err("worker failure");
        assert_eq!(error.to_string(), "stored dynamic client registration is corrupted: client secret verification unavailable");
    }
}

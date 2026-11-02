use super::*;
use crate::dcr_persistence::{create_dynamic_registration, load_dynamic_registration_by_token};
use crate::web::test_support::{sample_registered_client, setup_test_environment, TestResult};
use std::time::Duration;

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; credential expiry during a blocked verification worker"]
async fn credential_expiry_after_selection_is_refused_after_worker_completion() -> TestResult {
    let db = super::super::test_database::Database::create(false).await?;
    let result = async {
        let env = setup_test_environment(&db.pool).await?;
        let mut client = sample_registered_client("worker-expiry");
        client.token_endpoint_auth_method = "client_secret_basic".into();
        client.client_secret = Some("issued-worker-expiry-fixture".into());
        create_dynamic_registration(&db.pool, &env.issuer_host, &client, &["code".into()], "worker-expiry-owner", "worker-expiry").await?;
        let stored = load_dynamic_registration_by_token(&db.pool, &env.issuer_host, &client.client_id, "worker-expiry-owner").await?.ok_or("stored client")?;
        // Positive control uses the same production query, worker and final clock check.
        let mut tx = db.pool.begin().await?;
        super::super::lock_current_dynamic_registration(&mut tx, &stored).await?;
        verify_current_client_secret(&mut tx, &stored, "issued-worker-expiry-fixture",
            Arc::new(Arc::new(Semaphore::new(1)).try_acquire_owned()?)).await?;
        tx.rollback().await?;
        sqlx::query("UPDATE aegaeon.client_secrets SET expires_at=statement_timestamp()+interval '2 seconds' WHERE client_id=$1")
            .bind(stored.database_client_id).execute(&db.pool).await?;
        let before: serde_json::Value = sqlx::query_scalar("SELECT to_jsonb(d) FROM aegaeon.dynamic_client_registrations d WHERE client_id=$1")
            .bind(stored.database_client_id).fetch_one(&db.pool).await?;
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let other = db.pool.clone();
        let row = stored.clone();
        let pending = tokio::spawn(async move {
            let mut tx = other.begin().await?;
            super::super::lock_current_dynamic_registration(&mut tx, &row).await?;
            let mut entered = Some(entered);
            let outcome = verify_current_with(&mut tx, &row, "issued-worker-expiry-fixture",
                Arc::new(Arc::new(Semaphore::new(1)).try_acquire_owned().expect("fixture slot")),
                move |assertion, hash| {
                    let matched = crate::local_credentials::verify_password(assertion, hash);
                    entered.take().expect("one eligible hash").send(matched).expect("observed worker");
                    wait.recv_timeout(Duration::from_secs(10)).expect("bounded worker release");
                    matched
                }).await;
            tx.rollback().await?;
            outcome
        });
        assert!(tokio::time::timeout(Duration::from_secs(5), started).await??,
            "real Argon2 verification matched a row selected before expiration");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let expired: bool = sqlx::query_scalar("SELECT bool_and(expires_at<=statement_timestamp()) FROM aegaeon.client_secrets WHERE client_id=$1")
                    .bind(stored.database_client_id).fetch_one(&db.pool).await?;
                if expired { return Ok::<_, sqlx::Error>(()); }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await??;
        release.send(())?;
        assert!(matches!(tokio::time::timeout(Duration::from_secs(5), pending).await??,
            Err(DcrDatabaseError::ClientSecretMismatch)));
        let after: serde_json::Value = sqlx::query_scalar("SELECT to_jsonb(d) FROM aegaeon.dynamic_client_registrations d WHERE client_id=$1")
            .bind(stored.database_client_id).fetch_one(&db.pool).await?;
        assert_eq!(before, after);
        Ok::<(), Box<dyn std::error::Error>>(())
    }.await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}

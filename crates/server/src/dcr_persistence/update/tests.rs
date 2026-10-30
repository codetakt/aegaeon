use super::*;
use crate::web::test_support::{sample_registered_client, setup_test_environment, TestResult};
use std::{sync::Mutex, time::Duration};

mod cancellation;
mod closed_admission;
mod commit_boundary;
pub(super) use commit_boundary::at_commit_boundary;
mod shutdown;
pub(super) use cancellation::at_final_mutation;

async fn fixture(pool: &PgPool) -> TestResult<(DcrStoredClient, RegisteredClient)> {
    let env = setup_test_environment(pool).await?;
    let mut client = sample_registered_client("update-cleanup");
    client.token_endpoint_auth_method = "client_secret_basic".into();
    client.client_secret = Some("cleanup-test-credential".into());
    create_dynamic_registration(
        pool,
        &env.issuer_host,
        &client,
        &["code".into()],
        "cleanup-owner-token",
        "cleanup-create",
    )
    .await?;
    let stored = load_dynamic_registration_by_token(
        pool,
        &env.issuer_host,
        &client.client_id,
        "cleanup-owner-token",
    )
    .await?
    .ok_or("stored registration")?;
    Ok((stored, client))
}

async fn snapshot(pool: &PgPool) -> TestResult<serde_json::Value> {
    Ok(sqlx::query_scalar("SELECT jsonb_build_object('clients',(SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM aegaeon.clients c),'registrations',(SELECT jsonb_agg(to_jsonb(d) ORDER BY client_id) FROM aegaeon.dynamic_client_registrations d),'secrets',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM aegaeon.client_secrets s),'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM aegaeon.audit_events a))").fetch_one(pool).await?)
}

// Block the real SQLx pool-return callback after the transaction has ended.
// Admission must not be reusable until this last owned connection action ends.
fn gated_pool(pool: &PgPool) -> (PgPool, oneshot::Receiver<()>, oneshot::Sender<()>) {
    let (entered, observed) = oneshot::channel();
    let (release, wait) = oneshot::channel();
    let gate = Arc::new(Mutex::new(Some((entered, wait))));
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_release(move |_, _| {
            let gate = gate.lock().expect("gate mutex").take();
            Box::pin(async move {
                if let Some((entered, wait)) = gate {
                    let _ = entered.send(());
                    tokio::time::timeout(Duration::from_secs(10), wait)
                        .await
                        .expect("bounded pool return")
                        .ok();
                }
                Ok(true)
            })
        })
        .connect_lazy_with((*pool.connect_options()).clone());
    (pool, observed, release)
}

async fn mismatch_or_cancel(pool: &PgPool, cancel: bool) -> TestResult {
    let (stored, client) = fixture(pool).await?;
    let before = snapshot(pool).await?;
    let (limited, entered, release) = gated_pool(pool);
    let other = credentials::admission::for_persistence(true)?.ok_or("other slot")?;
    let mut blocker = pool.begin().await?;
    if cancel {
        sqlx::query("SELECT pg_advisory_xact_lock(754321)")
            .execute(&mut *blocker)
            .await?;
        // This trigger blocks after the registration writes, before the audit.
        sqlx::raw_sql("CREATE FUNCTION aegaeon.pause_update_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(754321); RETURN NEW; END $$; CREATE TRIGGER pause_update_audit BEFORE INSERT ON aegaeon.audit_events FOR EACH ROW EXECUTE FUNCTION aegaeon.pause_update_audit();").execute(pool).await?;
    }
    let connection_pool = limited.clone();
    let pending = tokio::spawn(async move {
        update_dynamic_registration(
            &connection_pool,
            &stored,
            &client,
            &["code".into()],
            "replacement-owner-token",
            DcrClientSecretChange::Preserve,
            Some(if cancel {
                "cleanup-test-credential"
            } else {
                "wrong-credential"
            }),
            "cleanup-update",
        )
        .await
    });
    let pending = if cancel {
        let waiting = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=754321 AND NOT granted)").fetch_one(pool).await?;
                if waiting { return Ok::<_, sqlx::Error>(()); }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await;
        if waiting.is_err() {
            blocker.rollback().await?;
            let _ = release.send(());
            let outcome = tokio::time::timeout(Duration::from_secs(5), pending).await??;
            return Err(
                format!("audit barrier was not reached; update outcome: {outcome:?}").into(),
            );
        }
        waiting??;
        pending.abort();
        assert!(pending.await.expect_err("cancel caller").is_cancelled());
        assert!(
            matches!(
                credentials::admission::for_persistence(true),
                Err(DcrDatabaseError::CredentialVerificationBusy)
            ),
            "cancelled query still holds admission"
        );
        // Keep the blocker held. PostgreSQL must cancel its waiting statement
        // at the configured deadline before the queued rollback can complete.
        None
    } else {
        // Keep the live request pending while its owned task returns the connection.
        assert!(!pending.is_finished());
        Some(pending)
    };
    tokio::time::timeout(Duration::from_secs(12), entered).await??;
    blocker.rollback().await?;
    assert!(
        matches!(
            credentials::admission::for_persistence(true),
            Err(DcrDatabaseError::CredentialVerificationBusy)
        ),
        "cleanup still owns admission"
    );
    assert_eq!(
        before,
        snapshot(pool).await?,
        "completed rollback restores every update effect"
    );
    release.send(()).map_err(|()| "release gate")?;
    if let Some(pending) = pending {
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(5), pending).await??,
            Err(DcrDatabaseError::ClientSecretMismatch)
        ));
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(permit) = credentials::admission::for_persistence(true) {
                drop(permit);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    drop(other);
    limited.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; real mismatch rollback and gated pool return"]
async fn credential_mismatch_retains_admission_through_completed_rollback() -> TestResult {
    let db = super::super::test_database::Database::create(false).await?;
    let result = mismatch_or_cancel(&db.pool, false).await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; caller cancellation after writes and before audit"]
async fn cancelled_update_rolls_back_writes_before_releasing_admission() -> TestResult {
    let db = super::super::test_database::Database::create(false).await?;
    let result = mismatch_or_cancel(&db.pool, true).await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}

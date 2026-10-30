use super::*;
use std::{
    collections::BTreeMap,
    sync::{mpsc, LazyLock},
};

struct MutationGate {
    entered: oneshot::Sender<()>,
    release: mpsc::Receiver<()>,
}

static FINAL_MUTATIONS: LazyLock<Mutex<BTreeMap<String, MutationGate>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

pub(in crate::dcr_persistence::update) fn at_final_mutation(request_id: &str) {
    let gate = FINAL_MUTATIONS
        .lock()
        .expect("mutation gates")
        .remove(request_id);
    if let Some(gate) = gate {
        let _ = gate.entered.send(());
        // Stay inside the actual final apply poll while another runtime thread
        // drops the caller. No synthetic replacement of transaction SQL.
        gate.release
            .recv_timeout(Duration::from_secs(5))
            .expect("bounded mutation gate");
    }
}

async fn wait_for_admission() -> TestResult {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(permit) = credentials::admission::for_persistence(true) {
                drop(permit);
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}

fn assert_busy() {
    assert!(
        matches!(
            credentials::admission::for_persistence(true),
            Err(DcrDatabaseError::CredentialVerificationBusy)
        ),
        "unfinished database work retains admission"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL CREATEDB; cancellation inside the final mutation poll"]
async fn cancelled_during_final_mutation_poll_rolls_back_all_effects() -> TestResult {
    let db = super::super::super::test_database::Database::create(false).await?;
    let result = async {
        let (stored, client) = fixture(&db.pool).await?;
        let before = snapshot(&db.pool).await?;
        let other = credentials::admission::for_persistence(true)?.ok_or("other slot")?;
        let request_id = uuid::Uuid::new_v4().to_string();
        let (entered, observed) = oneshot::channel();
        let (release, wait) = mpsc::channel();
        FINAL_MUTATIONS.lock().expect("mutation gates").insert(
            request_id.clone(),
            MutationGate {
                entered,
                release: wait,
            },
        );
        let pool = db.pool.clone();
        let caller = tokio::spawn(async move {
            update_dynamic_registration(
                &pool,
                &stored,
                &client,
                &["code".into()],
                "replacement-owner-token",
                DcrClientSecretChange::Preserve,
                Some("cleanup-test-credential"),
                &request_id,
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(5), observed).await??;
        caller.abort();
        assert!(caller.await.expect_err("cancel caller").is_cancelled());
        assert_busy();
        release.send(())?;
        wait_for_admission().await?;
        assert_eq!(
            before,
            snapshot(&db.pool).await?,
            "cancellation wins before commit admission"
        );
        drop(other);
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; actual SQLx setup and pool-return hooks"]
async fn cancelled_update_checkout_owns_setup_and_pool_return_without_mutation() -> TestResult {
    let db = super::super::super::test_database::Database::create(false).await?;
    let result = async {
        let (stored, client) = fixture(&db.pool).await?;
        let before = snapshot(&db.pool).await?;
        let (entered, observed) = oneshot::channel();
        let (release, wait) = oneshot::channel();
        let gate = Arc::new(Mutex::new(Some((entered, wait))));
        let (returned, returning) = oneshot::channel();
        let (return_release, return_wait) = oneshot::channel();
        let return_gate = Arc::new(Mutex::new(Some((returned, return_wait))));
        let limited = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(5))
            .after_connect(move |connection, _| {
                let gate = gate.lock().expect("checkout gate").take();
                Box::pin(async move {
                    sqlx::query("SELECT 1").execute(connection).await?;
                    if let Some((entered, wait)) = gate {
                        let _ = entered.send(());
                        let _ = tokio::time::timeout(Duration::from_secs(5), wait)
                            .await
                            .expect("bounded setup gate");
                    }
                    Ok(())
                })
            })
            .after_release(move |_, _| {
                let gate = return_gate.lock().expect("return gate").take();
                Box::pin(async move {
                    if let Some((entered, wait)) = gate {
                        let _ = entered.send(());
                        let _ = tokio::time::timeout(Duration::from_secs(5), wait)
                            .await
                            .expect("bounded return gate");
                    }
                    Ok(true)
                })
            })
            .connect_lazy_with((*db.pool.connect_options()).clone());
        let other = credentials::admission::for_persistence(true)?.ok_or("other slot")?;
        let pool = limited.clone();
        let caller = tokio::spawn(async move {
            update_dynamic_registration(
                &pool,
                &stored,
                &client,
                &["code".into()],
                "replacement-owner-token",
                DcrClientSecretChange::Preserve,
                Some("cleanup-test-credential"),
                "checkout-cancel",
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(5), observed).await??;
        caller.abort();
        assert!(caller.await.expect_err("cancel caller").is_cancelled());
        tokio::task::yield_now().await;
        assert_busy();
        release.send(()).map_err(|()| "release setup")?;
        tokio::time::timeout(Duration::from_secs(5), returning).await??;
        assert_busy();
        assert_eq!(
            before,
            snapshot(&db.pool).await?,
            "cancelled checkout cannot start mutation"
        );
        return_release.send(()).map_err(|()| "release return")?;
        wait_for_admission().await?;
        drop(other);
        limited.close().await;
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL; admission closes during actual final mutation poll"]
async fn closed_admission_during_final_mutation_rolls_back_before_commit() -> TestResult {
    let db = super::super::super::test_database::Database::create(false).await?;
    let result = async {
        let (stored, client) = fixture(&db.pool).await?;
        let before = snapshot(&db.pool).await?;
        let limit = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = Arc::new(limit.clone().try_acquire_owned()?);
        let request_id = Uuid::new_v4().to_string();
        let (entered, observed) = oneshot::channel();
        let (release, wait) = mpsc::channel();
        FINAL_MUTATIONS.lock().expect("mutation gates").insert(
            request_id.clone(),
            MutationGate {
                entered,
                release: wait,
            },
        );
        let pool = db.pool.clone();
        let caller = tokio::spawn(credentials::admission::with_test_admission(
            permit,
            async move {
                update_dynamic_registration(
                    &pool,
                    &stored,
                    &client,
                    &["code".into()],
                    "closed-after-write",
                    DcrClientSecretChange::Preserve,
                    None,
                    &request_id,
                )
                .await
            },
        ));
        tokio::time::timeout(Duration::from_secs(5), observed).await??;
        limit.close();
        release.send(())?;
        let result = tokio::time::timeout(Duration::from_secs(5), caller).await??;
        assert!(matches!(
            result,
            Err(DcrDatabaseError::CredentialVerificationBusy)
        ));
        assert_eq!(
            before,
            snapshot(&db.pool).await?,
            "completed rollback preserves all mutation effects"
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}

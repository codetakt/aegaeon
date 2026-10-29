use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

fn permit() -> OwnedSemaphorePermit {
    Arc::new(Semaphore::new(1))
        .try_acquire_owned()
        .expect("fixture admission")
}

#[tokio::test(flavor = "current_thread")]
async fn credential_verification_uses_worker_and_checks_both_overlaps() {
    let executor = std::thread::current().id();
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let (matched, _permit) = verify_hashes(
        vec![(first, "first".into()), (second, "second".into())],
        "assertion".into(),
        permit(),
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
    let error = verify_hashes(hashes, "private-assertion".into(), permit(), |_, _| {
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
        permit(),
        |_, _| panic!("injected worker failure"),
    )
    .await
    .expect_err("worker failure");
    assert_eq!(
        error.to_string(),
        "stored dynamic client registration is corrupted: client secret verification unavailable"
    );
}

#[tokio::test]
async fn credential_admission_refuses_before_database_and_exempts_absent_assertions() {
    let permits = CREDENTIAL_UPDATES
        .clone()
        .try_acquire_many_owned(2)
        .expect("all slots");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1/unused")
        .expect("lazy fixture pool");
    pool.close().await;
    assert!(matches!(
        begin_update(&pool, true).await,
        Err(DcrDatabaseError::CredentialVerificationBusy)
    ));
    assert!(matches!(
        begin_update(&pool, false).await,
        Err(DcrDatabaseError::Database(sqlx::Error::PoolClosed))
    ));
    drop(permits);
    assert!(matches!(
        begin_update(&pool, true).await,
        Err(DcrDatabaseError::Database(sqlx::Error::PoolClosed))
    ));
    assert_eq!(
        CREDENTIAL_UPDATES.available_permits(),
        MAX_CREDENTIAL_UPDATES
    );
}

#[tokio::test]
async fn cancelled_credential_caller_keeps_admission_until_worker_finishes() {
    let budget = Arc::new(Semaphore::new(1));
    let permit = budget.clone().try_acquire_owned().expect("slot");
    let (entered, started) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let mut entered = Some(entered);
    let pending = tokio::spawn(verify_hashes(
        vec![(Uuid::new_v4(), "hash".into())],
        "assertion".into(),
        permit,
        move |_, _| {
            entered
                .take()
                .expect("one hash")
                .send(())
                .expect("observed start");
            wait.recv_timeout(std::time::Duration::from_secs(10))
                .expect("bounded worker release");
            true
        },
    ));
    tokio::time::timeout(std::time::Duration::from_secs(5), started)
        .await
        .expect("start deadline")
        .expect("worker started");
    pending.abort();
    assert!(pending.await.expect_err("cancel caller").is_cancelled());
    assert!(
        budget.clone().try_acquire_owned().is_err(),
        "worker still owns admission"
    );
    release.send(()).expect("release worker");
    let _recovered = tokio::time::timeout(std::time::Duration::from_secs(5), budget.acquire())
        .await
        .expect("worker exit deadline")
        .expect("recovered admission");
}

#[tokio::test]
async fn completed_credential_worker_returns_admission_to_its_transaction() {
    let budget = Arc::new(Semaphore::new(1));
    let permit = budget.clone().try_acquire_owned().expect("slot");
    let (matched, permit) = verify_hashes(
        vec![(Uuid::new_v4(), "hash".into())],
        "assertion".into(),
        permit,
        |_, _| true,
    )
    .await
    .expect("verification");
    assert_eq!(matched.len(), 1);
    assert!(
        budget.clone().try_acquire_owned().is_err(),
        "transaction still owns admission"
    );
    drop(permit);
    assert_eq!(budget.available_permits(), 1);
}

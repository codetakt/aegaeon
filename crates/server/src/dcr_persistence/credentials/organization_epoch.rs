use super::*;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;
use crate::web::test_support::TestResult;
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

#[tokio::test]
#[ignore = "requires PostgreSQL; actual KDF worker retains witness after waiter cancellation"]
async fn pg_organizations_registration_credential_worker() -> TestResult {
    let witness = CallerFixture::new(Uuid::new_v4()).await?;
    let (release, wait) = std::sync::mpsc::channel();
    let result: TestResult = async {
        let hash = crate::local_credentials::hash_password("owned-registration-password")?;
        let permit = admission::for_persistence(true)?.ok_or("credential permit absent")?;
        let work = witness.begin().await?;
        let (entered, observed) = tokio::sync::oneshot::channel();
        let mut entered = Some(entered);
        let verified = Arc::new(AtomicBool::new(false));
        let check = verified.clone();
        work.store_scope(async {
            let mut pending = Box::pin(verify_hashes(
                vec![(Uuid::new_v4(), hash)],
                "owned-registration-password".into(), permit,
                move |password, hash| {
                    let valid = crate::local_credentials::verify_password(password, hash);
                    check.store(valid, Ordering::SeqCst);
                    if let Some(entered) = entered.take() { let _ = entered.send(()); }
                    wait.recv_timeout(Duration::from_secs(5)).expect("bounded credential worker gate");
                    valid
                },
            ));
            tokio::select! {
                result = &mut pending => Err::<(),Box<dyn std::error::Error>>(format!("KDF returned before gate: {result:?}").into()),
                result = tokio::time::timeout(Duration::from_secs(5),observed) => { result??; drop(pending); Ok(()) }
            }
        }).await??;
        let mut completion = tokio::spawn(work.complete());
        let early = tokio::time::timeout(Duration::from_millis(100), &mut completion).await;
        let pending = witness.pending().await?;
        release.send(())?;
        if early.is_ok() || pending != 1 {return Err("KDF worker lost Organizations ownership while still running".into());}
        tokio::time::timeout(Duration::from_secs(5), completion).await???;
        if !verified.load(Ordering::SeqCst) {return Err("actual credential verification did not succeed".into());}
        Ok(())
    }.await;
    let _ = release.send(());
    let cleanup = witness.finish().await.map_err(Into::into);
    result.and(cleanup)
}

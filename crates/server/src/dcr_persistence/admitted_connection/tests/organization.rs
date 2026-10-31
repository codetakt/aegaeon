use super::*;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; real runtime revision read and observed pool return"]
async fn pg_organizations_runtime_authority_read_retains_both_owners_through_pool_return(
) -> TestResult {
    let f = crate::organizations::repository_tests::Fixture::new().await?;
    let witness = CallerFixture::new(f.env.environment_id).await?;
    let result = exercise(&f, &witness).await;
    let cleanup = witness
        .finish()
        .await
        .map_err(|error| -> Box<dyn std::error::Error> { error.into() });
    f.cleanup(result.and(cleanup)).await
}

async fn exercise(
    f: &crate::organizations::repository_tests::Fixture,
    witness: &CallerFixture,
) -> TestResult {
    let ordinary =
        crate::runtime_configuration::load_active_runtime_configuration_revision_for_issuer_host(
            &f.pool,
            &f.env.issuer_host,
        )
        .await?;
    assert!(!ordinary.active_runtime_client_fingerprint().is_empty());
    let (entered, observed) = oneshot::channel();
    let (release, wait) = oneshot::channel();
    let gate = Arc::new(Mutex::new(Some((entered, wait))));
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(3))
        .after_release(move |_, _| {
            let gate = gate.lock().expect("gate").take();
            Box::pin(async move {
                if let Some((entered, wait)) = gate {
                    let _ = entered.send(());
                    tokio::time::timeout(Duration::from_secs(10), wait)
                        .await
                        .map_err(|_| sqlx::Error::PoolTimedOut)?
                        .map_err(|_| sqlx::Error::PoolClosed)?;
                }
                Ok(true)
            })
        })
        .connect_lazy_with((*f.pool.connect_options()).clone());
    let work = witness.begin().await?;
    let owner = work.admission().clone();
    let dcr_limit = Arc::new(tokio::sync::Semaphore::new(1));
    let dcr_owner = Arc::new(dcr_limit.clone().try_acquire_owned()?);
    let caller_pool = pool.clone();
    let host = f.env.issuer_host.clone();
    let (cancel, cancelled) = oneshot::channel();
    let caller = tokio::spawn(async move {
        owner.store_scope(admission::with_test_admission(dcr_owner, async {
            tokio::select! {
                result = crate::runtime_configuration::load_active_runtime_configuration_revision_for_issuer_host(&caller_pool, &host) => {
                    result.map_err(|e| e.to_string())?;
                    Ok::<_, String>(false)
                }
                _ = cancelled => Ok(true),
            }
        })).await
    });
    tokio::time::timeout(Duration::from_secs(5), observed).await??;
    cancel.send(()).map_err(|_| "caller cancellation")?;
    assert!(caller.await??.map_err(|e| format!("authority read: {e}"))?);
    let dcr_retained = dcr_limit.available_permits() == 0;
    let mut complete = tokio::spawn(work.complete());
    let early = tokio::time::timeout(Duration::from_millis(150), &mut complete).await;
    let pending = witness.pending().await?;
    // Release the real pool hook before assertions so the negative control also
    // finishes all owned work and leaves its failure observable.
    release.send(()).map_err(|_| "pool return release")?;
    let retained = early.is_err();
    let done = match early {
        Ok(done) => done?,
        Err(_) => tokio::time::timeout(Duration::from_secs(5), complete).await??,
    }?;
    tokio::time::timeout(Duration::from_secs(5), pool.close()).await?;
    assert!(
        retained && pending == 1,
        "actual runtime read must retain the witness through pool return"
    );
    assert!(
        dcr_retained,
        "overlapping DCR capacity must also remain owned"
    );
    assert_eq!(done.pending, 0);
    assert_eq!(dcr_limit.available_permits(), 1);
    assert!(!dcr_limit.is_closed());
    Ok(())
}

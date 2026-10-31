use super::*;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::oneshot;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; actual consent load refusal and observed pool cleanup"]
async fn pg_organizations_consent_load_refusal_retains_epoch_through_pool_return(
) -> crate::web::test_support::TestResult {
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
) -> crate::web::test_support::TestResult {
    let mut state = crate::web::test_support::test_app_state(f.pool.clone(), &f.env).await?;
    state.db_pool.close().await;
    let (entered, observed) = oneshot::channel();
    let (release, wait) = oneshot::channel();
    let gate = Arc::new(Mutex::new(Some((entered, wait))));
    state.db_pool = sqlx::postgres::PgPoolOptions::new()
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
    let response = work
        .store_scope(load(&state, "unissued", "unissued", "unissued"))
        .await?;
    assert!(response.is_err(), "absent consent must refuse");
    drop(response);
    tokio::time::timeout(Duration::from_secs(5), observed).await??;
    let mut complete = tokio::spawn(work.complete());
    let early = tokio::time::timeout(Duration::from_millis(150), &mut complete).await;
    let pending = witness.pending().await?;
    release.send(()).map_err(|_| "release")?;
    let retained = early.is_err();
    let done = match early {
        Ok(done) => done?,
        Err(_) => tokio::time::timeout(Duration::from_secs(5), complete).await??,
    }?;
    tokio::time::timeout(Duration::from_secs(5), state.db_pool.close()).await?;
    assert!(
        retained && pending == 1,
        "consent load refusal must retain actual cleanup ownership"
    );
    assert_eq!(done.pending, 0);
    Ok(())
}

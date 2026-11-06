use super::*;
use crate::{
    organizations::{repository_tests::Fixture, witness::tests::caller_fixture::CallerFixture},
    web::test_support::{test_app_state, TestResult},
};

#[tokio::test]
async fn organization_cleanup_blocking_failure_is_not_success() {
    let failed = AtomicBool::new(false);
    run_cleanup_blocking("fixture", Duration::from_secs(1), &failed, || Ok(())).await;
    assert!(!failed.load(Ordering::Relaxed));
    run_cleanup_blocking("fixture", Duration::from_secs(1), &failed, || {
        Err("injected store failure".into())
    })
    .await;
    assert!(failed.load(Ordering::Relaxed));
}

#[tokio::test]
async fn organization_cleanup_timeout_retains_blocking_owner() -> TestResult {
    let owner = crate::organizations::request_work::Admission::isolated_for_test()?;
    let failed = AtomicBool::new(false);
    let (release, wait) = std::sync::mpsc::channel();
    let (started, entered) = tokio::sync::oneshot::channel();
    let result = owner.store_scope(run_cleanup_blocking(
        "fixture",
        Duration::from_millis(50),
        &failed,
        move || {
            let _ = started.send(());
            wait.recv_timeout(Duration::from_secs(3))
                .map_err(|e| e.to_string())
        },
    ));
    let (result, entered) = tokio::join!(result, entered);
    result?;
    entered?;
    assert!(failed.load(Ordering::Relaxed));
    let completion = owner.completion_for_test();
    tokio::pin!(completion);
    let early = tokio::time::timeout(Duration::from_millis(20), &mut completion).await;
    release.send(())?;
    assert!(
        early.is_err(),
        "timed out child still owns cleanup admission"
    );
    tokio::time::timeout(Duration::from_secs(2), completion).await??;
    Ok(())
}

async fn observed(f: &Fixture) -> anyhow::Result<CallerFixture> {
    CallerFixture::with_observed_stores(
        f.env.environment_id,
        f.pool.connect_options().as_ref().clone(),
        redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?,
    )
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; actual cleanup pass within observed work"]
async fn shared_redis_organizations_observed_cleanup_normal_pass() -> TestResult {
    let f = Fixture::new().await?;
    let mut control = observed(&f).await?;
    let state = test_app_state(f.pool.clone(), &f.env).await?;
    let result = async {
        control.run(run_cleanup_pass(&state, 30)).await??;
        if control.pending().await? != 0 || control.observed_generation().await? != 1 {
            return Err("cleanup pass did not complete its observed generation".into());
        }
        Ok(())
    }
    .await;
    state.db_pool.close().await;
    let cleanup = control.finish().await.map_err(Into::into);
    f.cleanup(result.and(cleanup)).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; DB failure cannot make a cleanup pass successful"]
async fn shared_redis_organizations_observed_cleanup_database_failure() -> TestResult {
    let f = Fixture::new().await?;
    let control = observed(&f).await?;
    let state = test_app_state(f.pool.clone(), &f.env).await?;
    let result = async {
        state.db_pool.close().await;
        let outcome = control.run(run_cleanup_pass(&state, 30)).await;
        if matches!(outcome, Ok(Ok(()))) {
            return Err("failed DB cleanup was reported as successful".into());
        }
        Ok(())
    }
    .await;
    state.db_pool.close().await;
    let cleanup = control.finish().await.map_err(Into::into);
    f.cleanup(result.and(cleanup)).await
}

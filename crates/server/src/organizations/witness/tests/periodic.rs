//! Actual durable slots across idle periods, shutdown, cancellation and fencing.
use super::*;
use crate::organizations::{
    request_work::{async_store, Admission as Local},
    witness::{dispatch::periodic, work::Starter},
};
use crate::runtime_restart::{RuntimeRestartRequest, RuntimeRestartState};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

fn stop(restart: &RuntimeRestartState) {
    restart.request_restart(RuntimeRestartRequest::runtime_authority_unavailable(
        "periodic-test",
        "issuer.example",
        "periodic",
    ));
}

async fn drained(control: &mut Control, f: &Fixture, scope: Scope) -> TestResult {
    tokio::time::timeout(Duration::from_secs(4), async {
        while control.current(scope).await?.pending != 0
            || dispatch::parent_pending(f, scope).await? != 0
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

async fn observation(
    f: &mut Fixture,
    scope: Scope,
) -> anyhow::Result<(i32, i64, Uuid, Option<String>)> {
    Ok(sqlx::query_as("SELECT slot,generation,worker_id,finished_wal::text FROM organization_witness.store_observations WHERE environment_id=$1")
        .bind(scope.environment_id).fetch_one(&mut f.owner).await?)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; every periodic pass owns a fresh actual slot"]
async fn shared_redis_organizations_periodic_fresh_passes_and_idle_release() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (mut control, scope, target) = dispatch::setup(&mut f).await?;
        let restart = RuntimeRestartState::new();
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let (entered, mut ready) = tokio::sync::mpsc::unbounded_channel();
        let runner = tokio::spawn(periodic::run(1, restart.clone(), move || {
            let (count, restart, entered) = (count.clone(), restart.clone(), entered.clone());
            Ok(target
                .clone()
                .dispatch(Local::isolated_for_test()?, move || {
                    let admitted = async_store::current_epoch_owner(scope.environment_id).is_ok();
                    async move {
                        if !admitted {
                            return Err(Error::Refused);
                        }
                        let n = count.fetch_add(1, Ordering::SeqCst) + 1;
                        let _ = entered.send(n);
                        if n == 2 {
                            stop(&restart);
                        }
                        Ok(())
                    }
                }))
        }));
        anyhow::ensure!(
            tokio::time::timeout(Duration::from_secs(4), ready.recv()).await? == Some(1)
        );
        drained(&mut control, &f, scope).await?;
        let first = observation(&mut f, scope).await?;
        anyhow::ensure!(
            first.3.is_some(),
            "first pass did not finish its observation"
        );
        anyhow::ensure!(
            observed.load(Ordering::SeqCst) == 1 && !runner.is_finished(),
            "idle pass retained work or next pass ran early"
        );
        tokio::time::timeout(Duration::from_secs(4), runner).await???;
        anyhow::ensure!(observed.load(Ordering::SeqCst) == 2);
        anyhow::ensure!(control.current(scope).await?.pending == 0);
        let second = observation(&mut f, scope).await?;
        // The finite catalog reuses the first free slot, advancing its generation.
        anyhow::ensure!(second.0 == first.0 && second.1 == first.1 + 1);
        anyhow::ensure!(second.2 != first.2 && second.3.is_some());
        anyhow::ensure!(dispatch::parent_pending(&f, scope).await? == 0);
        control.close().await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

async fn interruption(cancel_waiter: bool) -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (mut control, scope, target) = dispatch::setup(&mut f).await?;
        let (entered, ready) = tokio::sync::oneshot::channel();
        let (release, wait) = tokio::sync::oneshot::channel();
        let mut inputs = Some((entered, wait));
        let restart = RuntimeRestartState::new();
        let runner = tokio::spawn(periodic::run(1, restart.clone(), move || {
            let (entered, wait) = inputs.take().ok_or(Error::Refused)?;
            Ok(target
                .clone()
                .dispatch(Local::isolated_for_test()?, move || async move {
                    let _ = entered.send(());
                    tokio::time::timeout(Duration::from_secs(4), wait)
                        .await
                        .map_err(|_| Error::Deadline)?
                        .map_err(|_| Error::Refused)?;
                    Ok(())
                }))
        }));
        tokio::time::timeout(Duration::from_secs(4), ready).await??;
        stop(&restart);
        if cancel_waiter {
            runner.abort();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let retained = control.current(scope).await?.pending == 1
            && dispatch::parent_pending(&f, scope).await? == 1;
        let returned_early = !cancel_waiter && runner.is_finished();
        // Always release and drain before reporting a mutant's early-return failure.
        let _ = release.send(());
        let outcome = tokio::time::timeout(Duration::from_secs(4), runner).await?;
        if cancel_waiter {
            anyhow::ensure!(outcome.unwrap_err().is_cancelled());
        } else {
            outcome??;
        }
        drained(&mut control, &f, scope).await?;
        anyhow::ensure!(dispatch::parent_pending(&f, scope).await? == 0);
        control.close().await?;
        anyhow::ensure!(retained, "active periodic pass lost its durable owner");
        anyhow::ensure!(
            !returned_early,
            "restart returned before active work completed"
        );
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; restart drains actual active work"]
async fn shared_redis_organizations_periodic_restart_drains_active_pass() -> TestResult {
    interruption(false).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; cancelled scheduler retains actual active work"]
async fn shared_redis_organizations_periodic_cancelled_waiter_retains_pass() -> TestResult {
    interruption(true).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; a new pass rechecks the actual fence"]
async fn shared_redis_organizations_periodic_refuses_new_pass_after_fence() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (mut control, scope, target) = dispatch::setup(&mut f).await?;
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let (entered, mut ready) = tokio::sync::mpsc::unbounded_channel();
        let runner = tokio::spawn(periodic::run(1, RuntimeRestartState::new(), move || {
            let (count, entered) = (count.clone(), entered.clone());
            Ok(target
                .clone()
                .dispatch(Local::isolated_for_test()?, move || async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    let _ = entered.send(());
                    Ok(())
                }))
        }));
        tokio::time::timeout(Duration::from_secs(4), ready.recv()).await?;
        drained(&mut control, &f, scope).await?;
        control.fence(scope, Uuid::new_v4(), 3).await?;
        anyhow::ensure!(tokio::time::timeout(Duration::from_secs(4), runner)
            .await??
            .is_err());
        anyhow::ensure!(observed.load(Ordering::SeqCst) == 1);
        anyhow::ensure!(control.current(scope).await?.is_drained_fence());
        anyhow::ensure!(dispatch::parent_pending(&f, scope).await? == 0);
        control.close().await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; completed operation failure is not retried"]
async fn shared_redis_organizations_periodic_stops_after_operation_failure() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (mut control, scope, target) = dispatch::setup(&mut f).await?;
        let mut attempts = 0;
        let result = periodic::run(1, RuntimeRestartState::new(), || {
            attempts += 1;
            Ok(target
                .clone()
                .dispatch(Local::isolated_for_test()?, || async {
                    Err(Error::Refused)
                }))
        })
        .await;
        anyhow::ensure!(result.is_err() && attempts == 1);
        anyhow::ensure!(control.current(scope).await?.pending == 0);
        anyhow::ensure!(dispatch::parent_pending(&f, scope).await? == 0);
        control.close().await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

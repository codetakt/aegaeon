//! Same dispatch implementation with actual isolated stores; local fixture
//! transports do not qualify the production connector or restore domain.
use super::*;
use crate::organizations::{
    request_work::{async_store, Admission as Local, CapacityClass},
    witness::work::{HttpExecution, ResponseLimit, Starter},
};
use axum::{
    body::{to_bytes, Body},
    http::Method,
    response::Response,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

pub(super) use super::admission_execution::{active as setup, parent_pending};

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; closure construction follows actual observed admission"]
async fn shared_redis_organizations_dispatch_constructs_inside_owned_scope() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (mut maintenance, scope, target) = setup(&mut f).await?;
        let called = Arc::new(AtomicBool::new(false));
        let check = called.clone();
        let execution = target.clone().dispatch(Local::isolated_for_test()?, move || {
            check.store(true, Ordering::SeqCst);
            // Runs while constructing the future, not just while polling it.
            let admitted = async_store::current_epoch_owner(scope.environment_id).is_ok();
            async move { admitted }
        });
        anyhow::ensure!(execution.result().await?, "closure was constructed outside admitted scope");
        anyhow::ensure!(called.load(Ordering::SeqCst));
        anyhow::ensure!(maintenance.current(scope).await?.pending == 0);
        let completed: i64 = sqlx::query_scalar("SELECT count(*) FROM organization_witness.store_observations WHERE environment_id=$1 AND finished_wal IS NOT NULL")
            .bind(scope.environment_id).fetch_one(&mut f.owner).await?;
        anyhow::ensure!(completed == 1);
        anyhow::ensure!(parent_pending(&f, scope).await? == 0);
        maintenance.close().await?;
        Ok(())
    }.await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; fenced selection never constructs caller work"]
async fn shared_redis_organizations_dispatch_refuses_fenced_selection_before_closure() -> TestResult
{
    let mut f = Fixture::new().await?;
    let result = async {
        let (mut maintenance, scope, target) = setup(&mut f).await?;
        maintenance.fence(scope, Uuid::new_v4(), 3).await?;
        let called = Arc::new(AtomicBool::new(false));
        let check = called.clone();
        let local = Local::isolated_for_test()?;
        let closed = local.closure_probe_for_test();
        let execution = target.clone().dispatch(local, move || {
            check.store(true, Ordering::SeqCst);
            async {}
        });
        anyhow::ensure!(execution.result().await.is_err());
        anyhow::ensure!(
            !called.load(Ordering::SeqCst),
            "fenced operation was constructed"
        );
        anyhow::ensure!(
            !closed.is_closed(),
            "confirmed child refusal permits parent cleanup"
        );
        anyhow::ensure!(maintenance.current(scope).await?.is_drained_fence());
        anyhow::ensure!(parent_pending(&f, scope).await? == 0);
        maintenance.close().await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; unpolled caller loss retains admitted work"]
async fn shared_redis_organizations_dispatch_detaches_before_response_poll() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (mut maintenance, scope, target) = setup(&mut f).await?;
        let (entered, ready) = tokio::sync::oneshot::channel();
        let (release, wait) = tokio::sync::oneshot::channel();
        let execution = target
            .clone()
            .dispatch(Local::isolated_for_test()?, move || {
                let admitted = async_store::current_epoch_owner(scope.environment_id).is_ok();
                async move {
                    let _ = entered.send(admitted);
                    let _ = tokio::time::timeout(Duration::from_secs(5), wait).await;
                }
            });
        drop(execution);
        anyhow::ensure!(tokio::time::timeout(Duration::from_secs(3), ready).await??);
        anyhow::ensure!(maintenance.current(scope).await?.pending == 1);
        anyhow::ensure!(parent_pending(&f, scope).await? == 1);
        anyhow::ensure!(maintenance.fence(scope, Uuid::new_v4(), 3).await?.pending == 1);
        let _ = release.send(());
        tokio::time::timeout(Duration::from_secs(5), async {
            while maintenance.current(scope).await?.pending != 0
                || parent_pending(&f, scope).await? != 0
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        anyhow::ensure!(maintenance.current(scope).await?.is_drained_fence());
        anyhow::ensure!(parent_pending(&f, scope).await? == 0);
        maintenance.close().await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; finite and snapshot bodies retain actual scope"]
async fn shared_redis_organizations_dispatch_http_retains_body_owner() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (mut maintenance, scope, target) = setup(&mut f).await?;
        for class in [CapacityClass::Ordinary, CapacityClass::Snapshot] {
            let execution = HttpExecution::dispatch(
                target.clone(),
                Local::isolated_class_for_test(class)?,
                Method::GET,
                ResponseLimit::Organization,
                move || {
                    let admitted = async_store::current_epoch_owner(scope.environment_id).is_ok();
                    async move {
                        Response::new(Body::from_stream(tokio_stream::StreamExt::map(
                            tokio_stream::once(()),
                            move |()| {
                                let owned = admitted
                                    && async_store::current_epoch_owner(scope.environment_id)
                                        .is_ok();
                                if owned {
                                    Ok("owned")
                                } else {
                                    Err(std::io::Error::other("unowned body"))
                                }
                            },
                        )))
                    }
                },
            );
            let response = execution.response().await?;
            anyhow::ensure!(to_bytes(response.into_body(), 16).await?.as_ref() == b"owned");
            anyhow::ensure!(maintenance.current(scope).await?.pending == 0);
        }
        anyhow::ensure!(parent_pending(&f, scope).await? == 0);
        maintenance.close().await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

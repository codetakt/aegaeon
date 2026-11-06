use super::*;
use std::sync::Arc;
use tokio::sync::{Notify, Semaphore};

#[tokio::test]
#[ignore = "requires PostgreSQL; late auxiliary pool returns are drained before fixture teardown"]
async fn pg_cleanup_drains_late_auxiliary_pool_return() -> ManagementTestResult {
    let (control, pool, name) = super::super::database().await?;
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Semaphore::new(0));
    let (seen, gate) = (entered.clone(), release.clone());
    let auxiliary = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_release(move |_, _| {
            let (seen, gate) = (seen.clone(), gate.clone());
            Box::pin(async move {
                seen.notify_one();
                gate.acquire_owned()
                    .await
                    .map_err(|_| sqlx::Error::PoolClosed)?
                    .forget();
                Ok(true)
            })
        })
        .connect_lazy_with(control.connect_options().as_ref().clone().database(&name));
    let held = auxiliary.acquire().await?;
    drop(held);
    tokio::time::timeout(Duration::from_secs(5), entered.notified()).await?;
    let closing = auxiliary.clone();
    let worker = tokio::spawn(async move { close_pool(&closing).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while !auxiliary.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    release.add_permits(1);
    let closed = tokio::time::timeout(Duration::from_secs(7), worker).await??;
    let result: ManagementTestResult = if closed.is_ok() && auxiliary.size() == 0 {
        Ok(())
    } else {
        Err("auxiliary cleanup missed the actual late return".into())
    };
    // Preserve the original negative outcome, then drain its probe explicitly.
    drain(&auxiliary).await;
    finish(
        result,
        cleanup_pools(control, vec![pool, auxiliary], &name).await,
    )
}

use super::*;
use std::{future::Future, sync::Arc, task::Poll};
use tokio::sync::Notify;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; controlled late pool return and actual session fence"]
async fn pg_lifecycle_close_drains_a_connection_returned_during_close() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let pool = f.selected.pool(
        PgPoolOptions::new().max_connections(1).after_release({
            let entered = entered.clone();
            let release = release.clone();
            move |_, _| {
                let entered = entered.clone();
                let release = release.clone();
                Box::pin(async move {
                    entered.notify_one();
                    release.notified().await;
                    Ok(true)
                })
            }
        }),
        f.endpoint.clone(),
    );
    let connection = pool.acquire().await?;
    drop(connection);
    tokio::time::timeout(Duration::from_secs(3), entered.notified()).await?;

    let closing = close_pool(&pool);
    tokio::pin!(closing);
    // The return task passed SQLx's is_closed check but cannot publish the
    // idle connection yet. Poll closure into its checked-out-permit wait.
    std::future::poll_fn(|context| {
        assert!(closing.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    assert!(pool.is_closed());
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(3), closing).await?;
    assert_eq!(pool.size(), 0, "close must drain the late-returned session");
    wait_runtime_release(&f.database).await?;
    f.activate(Some(f.selected.generation), Uuid::new_v4())
        .await?;
    f.finish().await
}

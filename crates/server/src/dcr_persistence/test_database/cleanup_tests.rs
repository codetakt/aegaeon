use super::*;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Notify, Semaphore};

#[tokio::test]
#[ignore = "requires PostgreSQL; deterministic late administrator return must be drained"]
async fn pg_owned_database_cleanup_drains_late_admin_return() -> anyhow::Result<()> {
    let mut database = Database::create(false).await?;
    // Replace this fixture's idle administrator pool with a one-connection
    // pool whose return can be held across close's final permit wait.
    let options = database.admin.connect_options().as_ref().clone();
    database.admin.close().await;
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Semaphore::new(0));
    let (seen, gate) = (entered.clone(), release.clone());
    database.admin = PgPoolOptions::new()
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
        .connect_lazy_with(options);
    let observed = database.admin.clone();
    let connection = database.admin.acquire().await?;
    drop(connection);
    tokio::time::timeout(Duration::from_secs(5), entered.notified()).await?;
    let cleanup = tokio::spawn(database.cleanup());
    tokio::time::timeout(Duration::from_secs(5), async {
        while !observed.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    release.add_permits(1);
    let result = tokio::time::timeout(Duration::from_secs(7), cleanup).await??;
    // Even a negative control explicitly closes this retained probe after its
    // original result; this never turns an unsuccessful cleanup into success.
    observed.close().await;
    result?;
    anyhow::ensure!(observed.size() == 0);
    Ok(())
}

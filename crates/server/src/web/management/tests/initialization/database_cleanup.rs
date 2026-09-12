//! Tear down only the disposable database created by the initialization fixture.
use super::{ManagementTestResult, PgPool};
use std::time::Duration;

pub(super) async fn cleanup(control: PgPool, pool: PgPool, name: &str) -> anyhow::Result<()> {
    let result = async {
        // SQLx sends Terminate and closes the client socket without a server
        // acknowledgement. Wait for PostgreSQL to retire those backends before
        // DROP DATABASE; a leaked connection must still fail within the bound.
        close_connections(&control, &pool, name, Duration::from_secs(5)).await?;
        sqlx::query(&format!("DROP DATABASE {name}"))
            .execute(&control)
            .await?;
        Ok(())
    }
    .await;
    control.close().await;
    result
}

async fn close_connections(
    control: &PgPool,
    pool: &PgPool,
    name: &str,
    limit: Duration,
) -> anyhow::Result<()> {
    tokio::time::timeout(limit, async {
        loop {
            pool.close().await;
            if pool.size() == 0 {
                break;
            }
            // SQLx 0.8.6 can return from close after a late release wakes its
            // final semaphore wait, leaving that connection in the idle queue.
            // Drain it too, while keeping unreturned leases within this deadline.
            tokio::task::yield_now().await;
        }
        loop {
            let connected: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = $1)",
            )
            .bind(name)
            .fetch_one(control)
            .await?;
            if !connected {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("connections to disposable database {name} did not close"))?
}

pub(super) fn finish(
    scenario: ManagementTestResult,
    cleanup: anyhow::Result<()>,
) -> ManagementTestResult {
    match (scenario, cleanup) {
        (result, Ok(())) => result,
        (Ok(()), Err(error)) => Err(error.context("disposable database cleanup failed").into()),
        (Err(scenario), Err(cleanup)) => Err(anyhow::anyhow!(
            "test scenario failed: {scenario:?}; disposable database cleanup also failed: {cleanup:#}"
        )
        .into()),
    }
}

#[test]
fn cleanup_does_not_hide_scenario_failures() {
    assert!(finish(Ok(()), Ok(())).is_ok());
    assert_eq!(
        finish(Err("scenario failure".into()), Ok(()))
            .unwrap_err()
            .to_string(),
        "scenario failure"
    );
    assert!(finish(Ok(()), Err(anyhow::anyhow!("cleanup failure"))).is_err());
    let both = finish(
        Err(anyhow::anyhow!("scenario cause")
            .context("scenario failure")
            .into()),
        Err(anyhow::anyhow!("cleanup failure")),
    )
    .unwrap_err()
    .to_string();
    assert!(both.contains("scenario failure"));
    assert!(both.contains("scenario cause"));
    assert!(both.contains("cleanup failure"));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_cleanup_waits_for_owned_connections_and_rejects_leaks() -> ManagementTestResult {
    use sqlx::{Connection, PgConnection};

    let (control, pool, name) = super::database().await?;
    let scenario: ManagementTestResult = async {
        let mut held = PgConnection::connect_with(&pool.connect_options()).await?;
        pool.close().await;
        // A persistent connection is reported, never terminated or accepted.
        let error = close_connections(&control, &pool, &name, Duration::from_millis(100))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("did not close"));
        let alive: i32 = sqlx::query_scalar("SELECT 1").fetch_one(&mut held).await?;
        assert_eq!(alive, 1);

        // A pending cleanup waits until the owner actually releases its socket.
        let waiting = close_connections(&control, &pool, &name, Duration::from_secs(2));
        tokio::pin!(waiting);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut waiting)
                .await
                .is_err()
        );
        held.close().await?;
        waiting.await?;
        Ok(())
    }
    .await;
    finish(scenario, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_cleanup_bounds_wait_for_unreturned_pool_lease() -> ManagementTestResult {
    let (control, pool, name) = super::database().await?;
    let scenario: ManagementTestResult = async {
        let mut held = pool.acquire().await?;
        // The outer bound is a regression watchdog: an unbounded pool.close()
        // must fail this test instead of hanging the integration runner.
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            close_connections(&control, &pool, &name, Duration::from_millis(100)),
        )
        .await
        .expect("connection drain must be bounded even with a pooled lease")
        .unwrap_err();
        assert!(error.to_string().contains("did not close"));
        let alive: i32 = sqlx::query_scalar("SELECT 1").fetch_one(&mut *held).await?;
        assert_eq!(alive, 1);
        held.close().await?;
        close_connections(&control, &pool, &name, Duration::from_secs(2)).await?;
        Ok(())
    }
    .await;
    finish(scenario, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_cleanup_drains_a_connection_returned_after_close_starts() -> ManagementTestResult {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use tokio::sync::Notify;

    let (control, pool, name) = super::database().await?;
    let scenario: ManagementTestResult = async {
        close_connections(&control, &pool, &name, Duration::from_secs(2)).await?;
        let armed = Arc::new(AtomicBool::new(false));
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let late = super::PgPoolOptions::new()
            .max_connections(1)
            .after_release({
                let armed = Arc::clone(&armed);
                let entered = Arc::clone(&entered);
                let release = Arc::clone(&release);
                move |_, _| {
                    let armed = Arc::clone(&armed);
                    let entered = Arc::clone(&entered);
                    let release = Arc::clone(&release);
                    Box::pin(async move {
                        if armed.swap(false, Ordering::SeqCst) {
                            entered.notify_one();
                            release.notified().await;
                        }
                        Ok(true)
                    })
                }
            })
            .connect_with(pool.connect_options().as_ref().clone())
            .await?;
        let held = late.acquire().await?;
        armed.store(true, Ordering::SeqCst);
        drop(held);
        tokio::time::timeout(Duration::from_secs(2), entered.notified()).await?;
        let draining = close_connections(&control, &late, &name, Duration::from_secs(2));
        tokio::pin!(draining);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut draining)
                .await
                .is_err()
        );
        release.notify_one();
        draining.await?;
        assert_eq!(late.size(), 0);
        Ok(())
    }
    .await;
    finish(scenario, cleanup(control, pool, &name).await)
}

use super::*;
use sqlx::{Connection, PgConnection};
use tokio::time::{timeout, Instant};

#[tokio::test]
#[ignore = "requires PostgreSQL; a controlled pool return overlaps close without changing its deadline"]
async fn pg_device_fixture_pool_close_confirms_late_return() -> anyhow::Result<()> {
    use std::future::{poll_fn, Future};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::task::Poll;
    use tokio::sync::Semaphore;

    let armed = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(Semaphore::new(0));
    let release = Arc::new(Semaphore::new(0));
    let options = PgPoolOptions::new().max_connections(1).after_release({
        let armed = armed.clone();
        let entered = entered.clone();
        let release = release.clone();
        move |_, _| {
            let armed = armed.swap(false, Ordering::SeqCst);
            let entered = entered.clone();
            let release = release.clone();
            Box::pin(async move {
                if armed {
                    entered.add_permits(1);
                    release
                        .acquire()
                        .await
                        .map_err(|_| sqlx::Error::Protocol("pool return barrier closed".into()))?
                        .forget();
                }
                Ok(true)
            })
        }
    });
    let pool = options
        .connect(&std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?)
        .await?;
    let mut observer = match PgConnection::connect_with(&pool.connect_options()).await {
        Ok(observer) => observer,
        Err(error) => {
            let cleanup = timeout(Duration::from_secs(3), close_fixture_pool(&pool))
                .await
                .context("pool close after observer setup failed");
            return combine_result(Err(error.into()), cleanup);
        }
    };
    let mut backend = None;
    let result = async {
        let mut connection = pool.acquire().await?;
        let (pid, backend_start): (i32, String) = sqlx::query_as(
            "SELECT pid, backend_start::text FROM pg_stat_activity WHERE pid=pg_backend_pid()",
        )
        .fetch_one(&mut *connection)
        .await?;
        backend = Some(pid);
        armed.store(true, Ordering::SeqCst);
        drop(connection);
        timeout(Duration::from_secs(3), entered.acquire())
            .await
            .context("pool return did not reach the controlled barrier")??
            .forget();
        let close_deadline = Instant::now() + Duration::from_secs(3);
        let mut closing = Box::pin(close_fixture_pool(&pool));
        let pending = poll_fn(|cx| Poll::Ready(closing.as_mut().poll(cx).is_pending())).await;
        anyhow::ensure!(pending, "pool close did not wait for the controlled return");
        anyhow::ensure!(pool.is_closed());
        release.add_permits(1);
        tokio::time::timeout_at(close_deadline, closing)
            .await
            .context("pool close did not finish within its existing budget")?;
        let present: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE pid=$1 AND backend_start::text=$2)",
        )
        .bind(pid)
        .bind(&backend_start)
        .fetch_one(&mut observer)
        .await?;
        eprintln!(
            "device fixture close boundary: backend={pid}, backend_start={backend_start}, closed={}, size={}, idle_diagnostic={}, same_backend_present={present}",
            pool.is_closed(), pool.size(), pool.num_idle()
        );
        anyhow::ensure!(pool.size() == 0, "closed pool retained an owned connection");
        admin_backend_absent(&mut observer, pid).await?;
        Ok(())
    }
    .await;
    // Release a pending hook even if an earlier assertion failed. Independent
    // recovery preserves that failure and acts only on this newly created pool.
    release.add_permits(1);
    let cleanup = timeout(Duration::from_secs(3), close_fixture_pool(&pool))
        .await
        .context("independent controlled pool close timed out");
    let backend_cleanup = if let Some(pid) = backend {
        admin_backend_absent(&mut observer, pid).await
    } else {
        Ok(())
    };
    let observer_cleanup = timeout(Duration::from_secs(3), observer.close())
        .await
        .context("controlled pool observer close timed out")
        .and_then(|result| result.map_err(Into::into));
    let cleanup = combine_result(cleanup, backend_cleanup);
    let cleanup = combine_result(cleanup, observer_cleanup);
    eprintln!(
        "device fixture close independent recovery: source_result={result:?}, recovery_result={cleanup:?}, size={}",
        pool.size()
    );
    combine_result(result, cleanup)
}

// The observer and held connection are separate from the fixture's pool. They
// only connect to the same disposable supplier and the exact UUID-owned DB.
async fn connections(f: &Fixture) -> anyhow::Result<(PgConnection, PgConnection, i32, i32)> {
    let admin_options = f.admin.connect_options();
    let observer = PgConnection::connect_with(&admin_options).await?;
    let mut held =
        PgConnection::connect_with(&admin_options.as_ref().clone().database(&f.name)).await?;
    let held_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut held)
        .await?;
    let admin_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&f.admin)
        .await?;
    Ok((observer, held, held_pid, admin_pid))
}

async fn database_exists(observer: &mut PgConnection, name: &str) -> anyhow::Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1)")
            .bind(name)
            .fetch_one(observer)
            .await?,
    )
}

async fn admin_backend_absent(observer: &mut PgConnection, pid: i32) -> anyhow::Result<()> {
    timeout(Duration::from_secs(3), async {
        loop {
            let absent: bool =
                sqlx::query_scalar("SELECT NOT EXISTS(SELECT FROM pg_stat_activity WHERE pid=$1)")
                    .bind(pid)
                    .fetch_one(&mut *observer)
                    .await?;
            if absent {
                return Ok::<_, sqlx::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("source admin backend remained after fixture cleanup")??;
    Ok(())
}

// Independent recovery runs after the qualification result is recorded. It
// cannot turn a failed assertion into success and never stops a foreign backend.
async fn recover(
    mut observer: PgConnection,
    held: Option<PgConnection>,
    admin: &PgPool,
    admin_pid: i32,
    name: &str,
    result: anyhow::Result<()>,
) -> anyhow::Result<()> {
    let held_close = if let Some(held) = held {
        timeout(Duration::from_secs(3), held.close())
            .await
            .context("owned held connection close timed out")
            .and_then(|result| result.map_err(Into::into))
    } else {
        Ok(())
    };
    let admin_close = timeout(Duration::from_secs(3), close_fixture_pool(admin))
        .await
        .context("independent source admin close timed out");
    let database_cleanup = timeout(Duration::from_secs(3), async {
        admin_backend_absent(&mut observer, admin_pid).await?;
        loop {
            let absent: bool = sqlx::query_scalar(
                "SELECT NOT EXISTS(SELECT FROM pg_stat_activity WHERE datname=$1)",
            )
            .bind(name)
            .fetch_one(&mut observer)
            .await?;
            if absent {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if database_exists(&mut observer, name).await? {
            observer
                .execute(format!("DROP DATABASE {name}").as_str())
                .await?;
        }
        anyhow::ensure!(!database_exists(&mut observer, name).await?);
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("independent owned database recovery timed out")
    .and_then(|result| result);
    let observer_close = timeout(Duration::from_secs(3), observer.close())
        .await
        .context("independent observer close timed out")
        .and_then(|result| result.map_err(Into::into));
    let cleanup = combine_result(held_close, admin_close);
    let cleanup = combine_result(cleanup, database_cleanup);
    let cleanup = combine_result(cleanup, observer_close);
    eprintln!(
        "device fixture independent recovery: database={name}, source_result={result:?}, recovery_result={cleanup:?}"
    );
    combine_result(result, cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL; fixture waits for an observed live backend before ordinary DROP"]
async fn pg_device_fixture_cleanup_waits_for_owned_backend() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let name = f.name.clone();
    let admin = f.admin.clone();
    let (mut observer, held, held_pid, admin_pid) = connections(&f).await?;
    let mut held = Some(held);
    // Remove pool-return scheduling as the reason for the controlled hold.
    timeout(Duration::from_secs(3), close_fixture_pool(&f.pool)).await?;
    let mut cleanup = Box::pin(f.cleanup(Ok(())));
    let result = async {
        // Poll actual source cleanup while the known connection is still open.
        // Only after observing non-completion do we release that connection.
        let premature = timeout(Duration::from_millis(50), cleanup.as_mut()).await;
        anyhow::ensure!(
            premature.is_err(),
            "fixture completed while the owned backend was held: {premature:?}"
        );
        let live_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(held.as_mut().context("held connection missing")?)
            .await?;
        anyhow::ensure!(live_pid == held_pid);
        anyhow::ensure!(database_exists(&mut observer, &name).await?);
        eprintln!("device fixture held: database={name}, backend={held_pid}, cleanup_pending=true");
        held.take()
            .context("held connection missing")?
            .close()
            .await?;
        cleanup.as_mut().await?;
        anyhow::ensure!(admin.is_closed());
        admin_backend_absent(&mut observer, admin_pid).await?;
        anyhow::ensure!(!database_exists(&mut observer, &name).await?);
        eprintln!("device fixture released: database={name}, source_cleanup=success, admin_backend_absent=true, database_absent=true");
        Ok(())
    }
    .await;
    // Stop polling source work before independent recovery on any error.
    drop(cleanup);
    recover(observer, held, &admin, admin_pid, &name, result).await
}

#[derive(Debug)]
struct BodyFailure;
impl std::fmt::Display for BodyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original device fixture body failure")
    }
}
impl std::error::Error for BodyFailure {}

#[tokio::test]
#[ignore = "requires PostgreSQL; live backend refusal stays bounded and retains body and cleanup errors"]
async fn pg_device_fixture_cleanup_refuses_live_backend_and_keeps_body_error() -> anyhow::Result<()>
{
    for body_fails in [false, true] {
        let f = Fixture::new().await?;
        let name = f.name.clone();
        let admin = f.admin.clone();
        let (mut observer, mut held, held_pid, admin_pid) = connections(&f).await?;
        let result = async {
            let body = if body_fails {
                Err(BodyFailure.into())
            } else {
                Ok(())
            };
            let start = Instant::now();
            let outcome = timeout(Duration::from_secs(7), f.cleanup(body))
                .await
                .context("fixture exceeded its own cleanup budgets")?;
            let failure = match outcome {
                Err(failure) => failure,
                Ok(()) => anyhow::bail!("a held backend must refuse cleanup"),
            };
            anyhow::ensure!(start.elapsed() < Duration::from_secs(7));
            let detail = format!("{failure:#}");
            eprintln!(
                "device fixture refusal: database={name}, backend={held_pid}, body_fails={body_fails}, elapsed={:?}, error={detail}",
                start.elapsed()
            );
            anyhow::ensure!(detail.contains("waiting for database backends"));
            anyhow::ensure!(detail.contains(&held_pid.to_string()));
            if body_fails {
                anyhow::ensure!(failure.downcast_ref::<BodyFailure>().is_some());
                anyhow::ensure!(failure.root_cause().to_string() == BodyFailure.to_string());
                anyhow::ensure!(detail.contains("additional device fixture cleanup failure"));
            } else {
                anyhow::ensure!(failure.downcast_ref::<BodyFailure>().is_none());
            }
            anyhow::ensure!(admin.is_closed());
            admin_backend_absent(&mut observer, admin_pid).await?;
            anyhow::ensure!(database_exists(&mut observer, &name).await?);
            let live_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut held)
                .await?;
            anyhow::ensure!(
                live_pid == held_pid,
                "cleanup must not terminate the held backend"
            );
            eprintln!("device fixture retained: database={name}, backend={held_pid}, admin_backend_absent=true, database_present=true, held_backend_live=true");
            Ok(())
        }
        .await;
        recover(observer, Some(held), &admin, admin_pid, &name, result).await?;
    }
    Ok(())
}

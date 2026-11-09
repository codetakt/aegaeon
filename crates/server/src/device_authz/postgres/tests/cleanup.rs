use super::*;
use sqlx::{Connection, PgConnection};
use tokio::time::{timeout, Instant};

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
    let admin_close = timeout(Duration::from_secs(3), admin.close())
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
    timeout(Duration::from_secs(3), f.pool.close()).await?;
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

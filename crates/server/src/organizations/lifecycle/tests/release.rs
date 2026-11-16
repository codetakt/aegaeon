//! Bound server-side fence observation separately from client pool drainage.
use super::*;

pub(super) async fn wait_runtime_release(pool: &PgPool) -> anyhow::Result<()> {
    // This is a fixture observation budget, not a product shutdown deadline.
    // Closing a transport does not acknowledge PostgreSQL backend termination.
    wait_with_limit(pool, Duration::from_secs(10)).await
}

async fn wait_with_limit(pool: &PgPool, limit: Duration) -> anyhow::Result<()> {
    let mut refused = 0_u64;
    let mut holders = serde_json::Value::Null;
    let result = tokio::time::timeout(limit, async {
        loop {
            // Autocommit releases this probe's transaction lock before reply.
            let released: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1,$2)")
                .bind(LOCK_DOMAIN)
                .bind(LOCK_KEY)
                .fetch_one(pool)
                .await?;
            if released {
                return Ok::<_, sqlx::Error>(());
            }
            refused += 1;
            // Keep a bounded, database-specific observation, without query text.
            // A timeout must distinguish a real remaining holder from no reply.
            if refused == 1 || refused % 100 == 0 {
                holders = sqlx::query_scalar(
                    "SELECT COALESCE(jsonb_agg(to_jsonb(held)), '[]'::jsonb) FROM (SELECT l.pid,l.mode,l.granted,a.state,a.wait_event_type,a.wait_event FROM pg_locks l LEFT JOIN pg_stat_activity a ON a.pid=l.pid WHERE l.locktype='advisory' AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND l.classid::bigint=$1 AND l.objid::bigint=$2 AND l.objsubid=2 ORDER BY l.pid LIMIT 8) held",
                )
                .bind(i64::from(LOCK_DOMAIN))
                .bind(i64::from(LOCK_KEY))
                .fetch_one(pool)
                .await?;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    result.with_context(|| {
        format!(
            "runtime SQL sessions did not release the generation fence; refused_probes={refused}; latest_holders={holders}"
        )
    })??;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; actual delayed generation fence release"]
async fn pg_lifecycle_release_observation_waits_for_actual_delayed_holder() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let pool = f.pool(f.selected);
    let connection = pool.acquire().await?;
    let (closed, observed) = {
        let waiting = wait_runtime_release(&f.database);
        tokio::pin!(waiting);
        let premature = tokio::select! {
            result = &mut waiting => Some(result),
            _ = tokio::time::sleep(Duration::from_millis(3200)) => None,
        };
        // Always release the owned session before reporting an assertion failure.
        let closed = connection.close().await;
        close_pool(&pool).await;
        let observed = match premature {
            Some(result) => {
                result.and_then(|()| anyhow::bail!("live generation fence was accepted"))
            }
            None => waiting.await,
        };
        (closed, observed)
    };
    let cleanup = f.finish().await;
    closed?;
    observed?;
    cleanup
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; held fence must time out with actual owner evidence"]
async fn pg_lifecycle_release_observation_refuses_a_live_holder_at_deadline() -> anyhow::Result<()>
{
    let f = Fixture::new().await?;
    let pool = f.pool(f.selected);
    let mut connection = pool.acquire().await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *connection)
        .await?;
    let result = wait_with_limit(&f.database, Duration::from_millis(200)).await;
    let closed = connection.close().await;
    close_pool(&pool).await;
    let released = wait_runtime_release(&f.database).await;
    let cleanup = f.finish().await;
    closed?;
    released?;
    let failure = result.expect_err("live generation fence must not be accepted");
    let diagnostic = format!("{failure:#}");
    anyhow::ensure!(diagnostic.contains("refused_probes="));
    anyhow::ensure!(diagnostic.contains(&format!("\"pid\":{pid}")));
    anyhow::ensure!(diagnostic.contains("ShareLock"));
    cleanup
}

//! Bounded cleanup for a fixture's UUID-named disposable PostgreSQL database.
use serde_json::{json, Value};
use sqlx::PgPool;
use std::time::Duration;

mod tests;

pub(crate) fn quote_database_identifier(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn observation_summary(observations: &[Value]) -> String {
    // Serialize only the latest snapshot into a fixed buffer. In particular,
    // a large blocker list must not turn a cleanup failure into an unbounded log.
    let mut bytes = [0_u8; 4096];
    let (written, truncated) = {
        let mut writer = std::io::Cursor::new(bytes.as_mut_slice());
        let truncated = serde_json::to_writer(&mut writer, &observations.last()).is_err();
        (writer.position() as usize, truncated)
    };
    format!(
        "retained_observations={}; latest_observation={}; latest_truncated={truncated}",
        observations.len(),
        String::from_utf8_lossy(&bytes[..written])
    )
}

async fn drain_pool(pool: &PgPool) {
    // SQLx 0.8.6 may return a connection after close's idle-queue inspection,
    // before its final permit wait completes. Do not lose the pool handle then.
    loop {
        pool.close().await;
        if pool.size() == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

pub(crate) async fn close_pool(pool: &PgPool, limit: Duration) -> Result<(), sqlx::Error> {
    tokio::time::timeout(limit, drain_pool(pool))
        .await
        .map_err(|_| {
            sqlx::Error::Protocol(format!(
                "owned fixture pool close deadline; pool_size={}",
                pool.size()
            ))
        })
}

pub(crate) async fn wait_database_idle(
    admin: &PgPool,
    name: &str,
    observations: &mut Vec<Value>,
) -> Result<(), sqlx::Error> {
    let started = std::time::Instant::now();
    loop {
        // Inspect only the exact owned database, with bounded rows and no query text.
        let states: Value = sqlx::query_scalar(
            "SELECT COALESCE(jsonb_agg(to_jsonb(owned) ORDER BY pid),'[]'::jsonb) FROM (SELECT pid,state,wait_event_type,wait_event,backend_type,backend_start,state_change,pg_blocking_pids(pid) AS blockers FROM pg_stat_activity WHERE datname=$1 ORDER BY pid LIMIT 33) owned",
        ).bind(name).fetch_one(admin).await?;
        let elapsed = started.elapsed().as_millis();
        if observations
            .last()
            .is_none_or(|last| last["states"] != states)
            || observations
                .last()
                .and_then(|last| last["elapsed_ms"].as_u64())
                .is_none_or(|last| elapsed.saturating_sub(u128::from(last)) >= 1000)
        {
            if observations.len() == 64 {
                observations.remove(0);
            }
            observations.push(json!({"elapsed_ms": elapsed, "states": states}));
        }
        if states.as_array().is_some_and(Vec::is_empty) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Close client transports, observe server exit and ordinarily drop the owned DB.
/// The admin pool is closed independently even when the first phase fails.
pub(crate) async fn finish_database(
    admin: &PgPool,
    pool: &PgPool,
    name: &str,
    limit: Duration,
) -> Result<(), sqlx::Error> {
    let mut observations = Vec::new();
    let cleanup = tokio::time::timeout(limit, async {
        drain_pool(pool).await;
        wait_database_idle(admin, name, &mut observations).await?;
        // Quote the generated identifier; never terminate sessions or force DROP.
        sqlx::query(&format!(
            "DROP DATABASE {}",
            quote_database_identifier(name)
        ))
        .execute(admin)
        .await?;
        Ok::<_, sqlx::Error>(())
    })
    .await
    .map_err(|_| {
        sqlx::Error::Protocol(format!(
            "owned fixture cleanup deadline; pool_size={}; {}",
            pool.size(),
            observation_summary(&observations)
        ))
    })
    .and_then(|result| result);
    let admin_cleanup = tokio::time::timeout(limit, drain_pool(admin))
        .await
        .map_err(|_| {
            sqlx::Error::Protocol(format!(
                "owned fixture admin close deadline; pool_size={}",
                admin.size()
            ))
        });
    match (cleanup, admin_cleanup) {
        (Err(error), Err(admin_error)) => Err(sqlx::Error::Protocol(format!(
            "{error}; additional admin cleanup failure: {admin_error}"
        ))),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), result) => result,
    }
}

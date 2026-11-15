//! Exercise a real server-maintenance backend on the fixture's owned database.
use super::*;

async fn analyzing_worker(
    observer: &mut PgConnection,
    database: &str,
    relation: i64,
) -> anyhow::Result<Option<(i32, String)>> {
    Ok(sqlx::query_as(
        "SELECT a.pid,a.backend_start::text FROM pg_catalog.pg_stat_activity a \
         JOIN pg_catalog.pg_stat_progress_analyze p USING (pid) \
         WHERE a.datname=$1 AND p.relid::bigint=$2 \
         AND a.backend_type='autovacuum worker'",
    )
    .bind(database)
    .bind(relation)
    .fetch_optional(observer)
    .await?)
}

#[tokio::test]
#[ignore = "requires PostgreSQL autovacuum; observes a real worker before ordinary PAR fixture removal"]
async fn pg_par_fixture_cleanup_removes_database_with_autovacuum_worker() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let name = fixture.database.clone();
    let pool = fixture.pool.clone();
    let admin = fixture.admin.clone();
    let (mut observer, held, _, admin_pid) = connections(&fixture).await?;
    let mut held = Some(held);
    let result = timeout(Duration::from_secs(135), async {
        // Only this disposable table changes; the supplier's launcher and
        // cluster settings retain their ordinary values.
        sqlx::raw_sql(
            "CREATE TABLE public.par_cleanup_probe(i int, v text) WITH (\
             autovacuum_analyze_threshold=0,autovacuum_analyze_scale_factor=0,\
             autovacuum_vacuum_insert_threshold=-1,\
             autovacuum_vacuum_cost_delay=100,autovacuum_vacuum_cost_limit=1); \
             INSERT INTO public.par_cleanup_probe \
             SELECT i,repeat(md5(i::text),4) FROM generate_series(1,100000) i; \
             SELECT pg_catalog.pg_stat_force_next_flush();",
        )
        .execute(held.as_mut().context("held connection missing")?)
        .await?;
        let relation: i64 =
            sqlx::query_scalar("SELECT 'public.par_cleanup_probe'::regclass::oid::bigint")
                .fetch_one(held.as_mut().context("held connection missing")?)
                .await?;
        let worker = timeout(Duration::from_secs(120), async {
            loop {
                if let Some(worker) = analyzing_worker(&mut observer, &name, relation).await? {
                    break Ok::<_, anyhow::Error>(worker);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await??;
        let observed = Instant::now();
        while observed.elapsed() < Duration::from_millis(3200) {
            anyhow::ensure!(
                analyzing_worker(&mut observer, &name, relation)
                    .await?
                    .as_ref()
                    == Some(&worker),
                "the same real autovacuum worker must outlive the cleanup polling window"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        eprintln!(
            "observed PAR autovacuum worker {worker:?} for {:?}",
            observed.elapsed()
        );
        held.take()
            .context("held connection missing")?
            .close()
            .await?;
        anyhow::ensure!(
            analyzing_worker(&mut observer, &name, relation)
                .await?
                .as_ref()
                == Some(&worker)
        );
        timeout(Duration::from_secs(7), fixture.finish()).await??;
        anyhow::ensure!(!database_exists(&mut observer, &name).await?);
        anyhow::ensure!(analyzing_worker(&mut observer, &name, relation)
            .await?
            .is_none());
        anyhow::ensure!(admin.is_closed());
        admin_backend_absent(&mut observer, admin_pid).await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .map_err(anyhow::Error::from)
    .and_then(|result| result);
    // Recovery also runs if preparation or the source cleanup timed out.
    let pool_close = timeout(Duration::from_secs(3), close_fixture_pool(&pool))
        .await
        .context("independent PAR pool close timed out");
    let result = combine_result(result, pool_close);
    recover(observer, held, &admin, admin_pid, &name, result).await
}

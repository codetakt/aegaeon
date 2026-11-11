//! Exercise the real server-maintenance backend, not a client-controlled label.
use super::*;
use tokio::time::Instant;

async fn analyzing_worker(
    recovery: &mut Recovery,
    relation: i64,
) -> anyhow::Result<Option<(i32, String)>> {
    Ok(sqlx::query_as(
        "SELECT a.pid,a.backend_start::text FROM pg_catalog.pg_stat_activity a \
         JOIN pg_catalog.pg_stat_progress_analyze p USING (pid) \
         WHERE a.datname=$1 AND p.relid::bigint=$2 \
         AND a.backend_type='autovacuum worker'",
    )
    .bind(&recovery.database)
    .bind(relation)
    .fetch_optional(&mut recovery.observer)
    .await?)
}

#[tokio::test]
#[ignore = "requires PostgreSQL autovacuum; observes a real worker before ordinary removal"]
async fn pg_witness_fixture_cleanup_removes_database_with_autovacuum_worker() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let mut recovery = Recovery::new(&fixture).await?;
    let result = timeout(Duration::from_secs(135), async {
        // Only this disposable table changes. Keep the supplier's launcher and
        // cluster settings intact, including its ordinary one-minute naptime.
        // A bounded table scan with a low per-table cost budget keeps the same
        // real worker alive beyond the fixture's two-second polling window.
        sqlx::raw_sql(
            "CREATE TABLE public.witness_cleanup_probe(i int, v text) WITH (\
             autovacuum_analyze_threshold=0,autovacuum_analyze_scale_factor=0,\
             autovacuum_vacuum_insert_threshold=-1,\
             autovacuum_vacuum_cost_delay=100,autovacuum_vacuum_cost_limit=1); \
             INSERT INTO public.witness_cleanup_probe \
             SELECT i,repeat(md5(i::text),4) FROM generate_series(1,100000) i; \
             SELECT pg_catalog.pg_stat_force_next_flush();",
        )
        .execute(&mut fixture.owner)
        .await?;
        let relation: i64 =
            sqlx::query_scalar("SELECT 'public.witness_cleanup_probe'::regclass::oid::bigint")
                .fetch_one(&mut fixture.owner)
                .await?;
        let worker = timeout(Duration::from_secs(120), async {
            loop {
                if let Some(worker) = analyzing_worker(&mut recovery, relation).await? {
                    break Ok::<_, anyhow::Error>(worker);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await??;
        let observed = Instant::now();
        while observed.elapsed() < Duration::from_millis(2200) {
            anyhow::ensure!(
                analyzing_worker(&mut recovery, relation).await?.as_ref() == Some(&worker),
                "the same real autovacuum worker must outlive the cleanup polling window"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        anyhow::ensure!(analyzing_worker(&mut recovery, relation).await?.as_ref() == Some(&worker));
        eprintln!(
            "observed autovacuum worker {worker:?} for {:?}",
            observed.elapsed()
        );
        // The old all-backend predicate fails here. No FORCE, terminate-backend
        // call, manual VACUUM, or client impersonating the worker is involved.
        timeout(Duration::from_secs(5), fixture.finish()).await??;
        anyhow::ensure!(!recovery.database_exists().await?);
        anyhow::ensure!(analyzing_worker(&mut recovery, relation).await?.is_none());
        Ok::<_, anyhow::Error>(())
    })
    .await
    .map_err(anyhow::Error::from)
    .and_then(|result| result);
    let cleanup = recovery.recover(None).await;
    result.and(cleanup)
}

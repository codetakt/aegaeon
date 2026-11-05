use super::parent_admission::Parent;
use super::*;
use crate::organizations::store_observation::{Postgres, Redis};

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; record must observe the actual connection again"]
async fn shared_redis_organizations_store_progress_refuses_lost_primary_observer() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (mut primary, mut token) = links(&mut f, 0).await?;
        let (mut maintenance, scope, operation, selected, mut parent) = Parent::prepare(&mut f).await?;
        maintenance.pin_store_progress(scope, operation, 2, &mut primary, &mut token).await?;
        maintenance.activate(scope, operation, 2, &selected.acceptance_sha256).await?;
        let mut runtime = f.connect(Role::Runtime).await?;
        assert!(runtime.acquire(scope, &selected, Uuid::new_v4()).await.is_err());
        let admission = parent.acquire().await?;
        let observation = runtime.begin_store_observation(&admission).await?;
        let killed: Vec<bool> = sqlx::query_scalar("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=current_database() AND usename=$1 AND application_name='aegaeon-store-progress-test'")
            .bind(&f.runtime).fetch_all(&mut f.owner).await?;
        anyhow::ensure!(killed == vec![true], "exact actual observer terminated");
        anyhow::ensure!(observation.record(&mut runtime, &mut primary, &mut token).await.is_err(), "a retained observation cannot replace the lost connection");
        anyhow::ensure!(maintenance.current(scope).await?.pending == 1);
        primary.close().await?; token.close();
        parent.close(false).await?;
        runtime.close().await?; maintenance.close().await?;
        Ok(())
    }.await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

pub(super) async fn links(f: &mut Fixture, database: u32) -> anyhow::Result<(Postgres, Redis)> {
    links_named(f, database, "aegaeon-store-progress-test").await
}

pub(super) async fn links_named(
    f: &mut Fixture,
    database: u32,
    application: &str,
) -> anyhow::Result<(Postgres, Redis)> {
    // Explicit isolated observation privileges, not an ordinary runtime grant.
    f.owner
        .execute(
            format!(
                "GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO {}",
                f.runtime
            )
            .as_str(),
        )
        .await?;
    let primary = Postgres::observe(
        PgConnection::connect_with(
            &f.options
                .clone()
                .username(&f.runtime)
                .password(&f.runtime_password)
                .application_name(application),
        )
        .await?,
    )
    .await?;
    let client = redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?;
    let mut connection = client.get_multiplexed_async_connection().await?;
    redis::cmd("SELECT")
        .arg(database)
        .query_async::<()>(&mut connection)
        .await?;
    Ok((primary, Redis::observe(connection).await?))
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; actual store observations retained through fencing"]
async fn shared_redis_organizations_store_progress_retains_actual_observations() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (mut primary, mut token) = links(&mut f, 0).await?;
        let (mut maintenance, scope, operation, selected, mut parent) =
            Parent::prepare(&mut f).await?;
        let pinned = maintenance
            .pin_store_progress(scope, operation, 2, &mut primary, &mut token)
            .await?;
        let replay = maintenance
            .pin_store_progress(scope, operation, 2, &mut primary, &mut token)
            .await?;
        anyhow::ensure!(serde_json::to_value(pinned)? == serde_json::to_value(replay)?);
        maintenance
            .activate(scope, operation, 2, &selected.acceptance_sha256)
            .await?;
        let mut runtime = f.connect(Role::Runtime).await?;
        assert!(runtime
            .acquire(scope, &selected, Uuid::new_v4())
            .await
            .is_err());
        let admission = parent.acquire().await?;
        let observation = runtime.begin_store_observation(&admission).await?;
        anyhow::ensure!(runtime.begin_store_observation(&admission).await.is_err());
        maintenance.fence(scope, Uuid::new_v4(), 3).await?;
        let earlier = primary.observation().clone();
        primary.recheck(&earlier).await?;
        let progress = observation
            .record(&mut runtime, &mut primary, &mut token)
            .await?;
        let progress = serde_json::to_value(progress)?;
        anyhow::ensure!(
            progress["checkpoint"]["wal_position"].as_u64()
                >= progress["checkpoint"]["initial_wal"].as_u64()
        );
        anyhow::ensure!(
            maintenance.current(scope).await?.pending == 1,
            "observation is not completion"
        );
        primary.close().await?;
        token.close();
        runtime.complete(&admission).await?;
        anyhow::ensure!(maintenance.current(scope).await?.is_drained_fence());
        parent.close(true).await?;
        runtime.close().await?;
        maintenance.close().await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; different actual selected Redis database refuses"]
async fn shared_redis_organizations_store_progress_refuses_token_database_confusion() -> TestResult
{
    let mut f = Fixture::new().await?;
    let result = async {
        let (mut primary, mut token) = links(&mut f, 0).await?;
        let (mut wrong_primary, mut wrong_token) = links(&mut f, 1).await?;
        let (mut maintenance, scope, operation, selected, mut parent) =
            Parent::prepare(&mut f).await?;
        maintenance
            .pin_store_progress(scope, operation, 2, &mut primary, &mut token)
            .await?;
        maintenance
            .activate(scope, operation, 2, &selected.acceptance_sha256)
            .await?;
        let mut runtime = f.connect(Role::Runtime).await?;
        assert!(runtime
            .acquire(scope, &selected, Uuid::new_v4())
            .await
            .is_err());
        let admission = parent.acquire().await?;
        let observation = runtime.begin_store_observation(&admission).await?;
        anyhow::ensure!(observation
            .record(&mut runtime, &mut wrong_primary, &mut wrong_token)
            .await
            .is_err());
        anyhow::ensure!(maintenance.current(scope).await?.pending == 1);
        primary.close().await?;
        wrong_primary.close().await?;
        token.close();
        wrong_token.close();
        parent.close(false).await?;
        runtime.close().await?;
        maintenance.close().await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; missing selected progress never receives an observation handle"]
async fn shared_redis_organizations_store_progress_requires_explicit_prepared_pin() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (mut maintenance, scope, operation, selected, mut parent) =
            Parent::prepare(&mut f).await?;
        maintenance
            .activate(scope, operation, 2, &selected.acceptance_sha256)
            .await?;
        let mut runtime = f.connect(Role::Runtime).await?;
        assert!(runtime
            .acquire(scope, &selected, Uuid::new_v4())
            .await
            .is_err());
        let admission = parent.acquire().await?;
        anyhow::ensure!(runtime.begin_store_observation(&admission).await.is_err());
        anyhow::ensure!(maintenance.current(scope).await?.pending == 1);
        parent.close(false).await?;
        runtime.close().await?;
        maintenance.close().await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

use super::caller_fixture::CallerWork;
use super::*;
use crate::organizations::witness::deployment::DeploymentId;
use sqlx::postgres::PgPoolOptions;

async fn begin(f: &mut Fixture) -> anyhow::Result<(CallerWork, Control, Scope, sqlx::PgPool)> {
    let (maintenance, deployment, selected, scope, child_selection) = deployment::setup(f).await?;
    maintenance.close().await?;
    let parent = deployment::begin(f, deployment, &selected).await?;
    let child = parent
        .child(
            deployment::connect(f, Role::Runtime).await?,
            scope.environment_id,
            &child_selection,
            || async {
                store_progress::links_named(f, 0, "aegaeon-child-progress-test")
                    .await
                    .map_err(|_| Error::Refused)
            },
        )
        .await?;
    let work = CallerWork::observed(child, parent);
    let maintenance = f.connect(Role::Maintenance).await?;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(
            f.options
                .clone()
                .username(&f.runtime)
                .password(&f.runtime_password),
        )
        .await?;
    Ok((work, maintenance, scope, pool))
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; all actual connections share retained observations"]
async fn shared_redis_organizations_observed_work_completes_actual_stores() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (work, maintenance, scope, pool) = begin(&mut f).await?;
        let mut connection = work.admission().connection(&pool).await?;
        let value: i32 = sqlx::query_scalar("SELECT 42").fetch_one(connection.as_mut()?).await?;
        anyhow::ensure!(value == 42);
        connection.release().await;
        let client = redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?;
        let reply = work.blocking(move || -> redis::RedisResult<String> {
            redis::cmd("PING").query(&mut crate::redis_io::connect(&client)?)
        }).await??;
        anyhow::ensure!(reply == "PONG");
        let state = work.complete().await?;
        anyhow::ensure!(state.pending == 0);
        anyhow::ensure!(parent_pending(&f, scope).await? == 0);
        let completed: i64 = sqlx::query_scalar("SELECT count(*) FROM organization_witness.store_observations WHERE environment_id=$1 AND finished_wal IS NOT NULL")
            .bind(scope.environment_id).fetch_one(&mut f.owner).await?;
        anyhow::ensure!(completed == 1);
        pool.close().await;
        maintenance.close().await?;
        Ok(())
    }.await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; actual different primary database refuses before use"]
async fn shared_redis_organizations_observed_work_refuses_other_primary_database() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (work, mut maintenance, scope, pool) = begin(&mut f).await?;
        // Isolated test administrator observes another database on the same cluster.
        let other = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(f.options.clone().database("postgres"))
            .await?;
        anyhow::ensure!(
            work.admission().connection(&other).await.is_err(),
            "wrong primary was handed to repository code"
        );
        anyhow::ensure!(work.complete().await.is_err());
        anyhow::ensure!(maintenance.current(scope).await?.pending == 1);
        anyhow::ensure!(parent_pending(&f, scope).await? == 1);
        other.close().await;
        pool.close().await;
        maintenance.close().await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; actual different Redis database refuses before command"]
async fn shared_redis_organizations_observed_work_refuses_other_token_database() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (work, mut maintenance, scope, pool) = begin(&mut f).await?;
        let client = redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?;
        let mut info = client.get_connection_info().clone();
        info.redis.db = 1;
        let other = redis::Client::open(info)?;
        let result = work
            .blocking(move || -> redis::RedisResult<String> {
                redis::cmd("PING").query(&mut crate::redis_io::connect(&other)?)
            })
            .await?;
        anyhow::ensure!(
            result.is_err(),
            "wrong token database accepted an authority command"
        );
        anyhow::ensure!(work.complete().await.is_err());
        anyhow::ensure!(maintenance.current(scope).await?.pending == 1);
        anyhow::ensure!(parent_pending(&f, scope).await? == 1);
        pool.close().await;
        maintenance.close().await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; unsafe actual primary at cleanup cannot complete"]
async fn shared_redis_organizations_observed_work_checks_primary_cleanup() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (work, mut maintenance, scope, pool) = begin(&mut f).await?;
        let mut connection = work.admission().connection(&pool).await?;
        connection
            .as_mut()?
            .execute("SET synchronous_commit=off")
            .await?;
        connection.release().await;
        anyhow::ensure!(
            work.complete().await.is_err(),
            "unsafe actual data connection was released as completed"
        );
        anyhow::ensure!(maintenance.current(scope).await?.pending == 1);
        anyhow::ensure!(parent_pending(&f, scope).await? == 1);
        pool.close().await;
        maintenance.close().await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; lost final observer leaves completed data work pending"]
async fn shared_redis_organizations_observed_work_refuses_lost_final_observer() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (work, mut maintenance, scope, pool) = begin(&mut f).await?;
        let mut connection = work.admission().connection(&pool).await?;
        connection.as_mut()?.execute("SELECT 1").await?;
        connection.release().await;
        let killed: Vec<bool> = sqlx::query_scalar("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=current_database() AND usename=$1 AND application_name='aegaeon-child-progress-test'")
            .bind(&f.runtime).fetch_all(&mut f.owner).await?;
        anyhow::ensure!(killed == vec![true]);
        anyhow::ensure!(work.complete().await.is_err());
        anyhow::ensure!(maintenance.current(scope).await?.pending == 1);
        anyhow::ensure!(parent_pending(&f, scope).await? == 1);
        pool.close().await; maintenance.close().await?;
        Ok(())
    }.await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; response cancellation cannot finish observed data work"]
async fn shared_redis_organizations_observed_work_retains_cancelled_waiter() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (work, mut maintenance, scope, pool) = begin(&mut f).await?;
        let admission = work.admission().clone();
        let data_pool = pool.clone();
        let (entered, waiting) = tokio::sync::oneshot::channel();
        let (release, resumed) = tokio::sync::oneshot::channel();
        let waiter = tokio::spawn(work.execute(async move {
            let mut connection = admission.connection(&data_pool).await?;
            let _ = entered.send(());
            resumed
                .await
                .map_err(|_| sqlx::Error::Protocol("test release lost".into()))?;
            connection.as_mut()?.execute("SELECT 1").await?;
            connection.release().await;
            Ok::<(), sqlx::Error>(())
        }));
        tokio::time::timeout(Duration::from_secs(5), waiting).await??;
        waiter.abort();
        let _ = waiter.await;
        anyhow::ensure!(maintenance.current(scope).await?.pending == 1);
        anyhow::ensure!(parent_pending(&f, scope).await? == 1);
        release
            .send(())
            .map_err(|_| anyhow::anyhow!("owned worker was cancelled"))?;
        tokio::time::timeout(Duration::from_secs(5), async {
            while maintenance.current(scope).await?.pending != 0
                || parent_pending(&f, scope).await? != 0
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<(), anyhow::Error>(())
        })
        .await??;
        pool.close().await;
        maintenance.close().await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

pub(super) async fn parent_pending(f: &Fixture, scope: Scope) -> anyhow::Result<u32> {
    let mut control = deployment::connect(f, Role::Maintenance).await?;
    let state = control
        .pending(DeploymentId::new(scope.deployment_id)?)
        .await?;
    control.close().await?;
    Ok(state.state.pending)
}

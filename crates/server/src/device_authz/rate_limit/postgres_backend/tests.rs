use super::*;
use crate::{config::RuntimeStateNamespace, device_authz::VerificationRateLimiter};
use sqlx::{postgres::PgPoolOptions, Executor};
use std::sync::Arc;
use uuid::Uuid;

fn migration() -> &'static str {
    crate::organization_schema::component!("runtime_security_budgets")
}

struct Fixture {
    admin: PgPool,
    pool: PgPool,
    database: String,
}
impl Fixture {
    async fn new() -> anyhow::Result<Self> {
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?)
            .await?;
        let database = format!("security_budgets_{}", Uuid::new_v4().simple());
        admin
            .execute(format!("CREATE DATABASE {database}").as_str())
            .await?;
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(admin.connect_options().as_ref().clone().database(&database))
            .await?;
        pool.execute("CREATE SCHEMA aegaeon").await?;
        sqlx::raw_sql(migration()).execute(&pool).await?;
        Ok(Self {
            admin,
            pool,
            database,
        })
    }

    fn limiter(&self, namespace: &RuntimeStateNamespace) -> Arc<VerificationRateLimiter> {
        Arc::new(VerificationRateLimiter::from_postgres(
            self.pool.clone(),
            namespace,
            "test",
        ))
    }

    async fn finish(self) -> anyhow::Result<()> {
        self.pool.close().await;
        self.admin
            .execute(format!("DROP DATABASE {}", self.database).as_str())
            .await?;
        self.admin.close().await;
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; durable concurrent multi-bucket rate limits"]
async fn pg_security_budgets_atomic_concurrency_and_namespace() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let namespace = RuntimeStateNamespace::from_environment_id(Uuid::new_v4());
        let limiter = fixture.limiter(&namespace);
        let mut jobs = tokio::task::JoinSet::new();
        for index in 0..32 {
            let limiter = limiter.clone();
            jobs.spawn(async move {
                // Reverse order and duplicates must not charge twice or deadlock.
                let keys = if index % 2 == 0 {
                    vec!["a", "b", "a"]
                } else {
                    vec!["b", "a"]
                };
                limiter
                    .try_check_all_async(keys.into_iter().map(str::to_owned).collect())
                    .await
            });
        }
        let mut allowed = 0;
        while let Some(result) = jobs.join_next().await {
            allowed += usize::from(result?.map_err(anyhow::Error::msg)?);
        }
        anyhow::ensure!(allowed == 10, "concurrent attempts exceeded budget");
        anyhow::ensure!(!limiter
            .clone()
            .try_check_all_async(vec!["a".into(), "unused".into()])
            .await
            .map_err(anyhow::Error::msg)?);
        for _ in 0..10 {
            anyhow::ensure!(
                limiter
                    .clone()
                    .try_check_async("unused".into())
                    .await
                    .map_err(anyhow::Error::msg)?,
                "refused multi-bucket operation charged an available bucket"
            );
        }
        // Reconstructing the facade, or another worker, cannot replenish state.
        anyhow::ensure!(!fixture
            .limiter(&namespace)
            .try_check_async("a".into())
            .await
            .map_err(anyhow::Error::msg)?);
        let other = RuntimeStateNamespace::from_environment_id(Uuid::new_v4());
        anyhow::ensure!(fixture
            .limiter(&other)
            .try_check_async("a".into())
            .await
            .map_err(anyhow::Error::msg)?);
        Ok(())
    }
    .await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; expiration, bounded cleanup and refusal"]
async fn pg_security_budgets_expiry_cleanup_and_failure() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let namespace = RuntimeStateNamespace::from_environment_id(Uuid::new_v4());
        let limiter = fixture.limiter(&namespace);
        anyhow::ensure!(limiter.clone().try_check_with_limit_async("limited".into(), 1).await.map_err(anyhow::Error::msg)?);
        anyhow::ensure!(!limiter.clone().try_check_with_limit_async("limited".into(), 1).await.map_err(anyhow::Error::msg)?);
        sqlx::query("UPDATE aegaeon.runtime_security_budgets SET expires_at=clock_timestamp()-interval '1 second'")
            .execute(&fixture.pool).await?;
        anyhow::ensure!(limiter.clone().try_check_with_limit_async("limited".into(), 1).await.map_err(anyhow::Error::msg)?);
        // Batches are bounded; subsequent batches drain a larger expired backlog.
        sqlx::query("INSERT INTO aegaeon.runtime_security_budgets SELECT $1, decode(md5(n::text)||md5(n::text),'hex'),1,clock_timestamp()-interval '1 second' FROM generate_series(1,8193) n")
            .bind(namespace.flow_namespace("rate-limit", "test")).execute(&fixture.pool).await?;
        let progress = crate::runtime_security_cleanup::cleanup(&fixture.pool,
            &namespace.flow_namespace("rate-limit", "test"), crate::runtime_security_cleanup::Kind::Budget, 1)
            .await.map_err(anyhow::Error::msg)?;
        anyhow::ensure!(progress.removed == 4096 && progress.more);
        for invalid in [0, 257] {
            anyhow::ensure!(crate::runtime_security_cleanup::cleanup(&fixture.pool, "irrelevant",
                crate::runtime_security_cleanup::Kind::Budget, invalid).await.is_err());
        }
        limiter.clone().cleanup_async().await.map_err(anyhow::Error::msg)?;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_security_budgets").fetch_one(&fixture.pool).await?;
        anyhow::ensure!(count == 1);
        anyhow::ensure!(!limiter.clone().try_check_with_limit_async("limited".into(), 1).await.map_err(anyhow::Error::msg)?);
        anyhow::ensure!(limiter.clone().try_check_with_limit_async("zero".into(), 0).await.is_err());
        anyhow::ensure!(limiter.clone().try_check_all_async((0..17).map(|i| i.to_string()).collect()).await.is_err());
        sqlx::query("DROP FUNCTION aegaeon.consume_runtime_security_budget(text,bytea[],bigint,bigint)").execute(&fixture.pool).await?;
        anyhow::ensure!(limiter.try_check_async("new".into()).await.is_err(), "no volatile fallback on storage failure");
        Ok(())
    }.await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; transaction outcomes retain conservative budget"]
async fn pg_security_budgets_transaction_outcomes() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let query = "SELECT aegaeon.consume_runtime_security_budget('test',ARRAY[decode(repeat('ab',32),'hex')],1,60000)";
        let mut tx = fixture.pool.begin().await?;
        anyhow::ensure!(sqlx::query_scalar::<_, bool>(query).fetch_one(&mut *tx).await?);
        tx.rollback().await?;
        let mut tx = fixture.pool.begin().await?;
        anyhow::ensure!(sqlx::query_scalar::<_, bool>(query).fetch_one(&mut *tx).await?);
        tx.commit().await?;
        // A retry cannot reclaim an attempt merely because the caller discarded
        // the earlier result. This is a DB outcome check, not a network fault.
        anyhow::ensure!(!sqlx::query_scalar::<_, bool>(query).fetch_one(&fixture.pool).await?);
        for invalid in ["NULL", "ARRAY[]::bytea[]", "ARRAY[NULL]::bytea[]", "ARRAY[decode('ab','hex')]"] {
            anyhow::ensure!(sqlx::query(&format!("SELECT aegaeon.consume_runtime_security_budget('test',{invalid},1,60000)")).execute(&fixture.pool).await.is_err());
        }
        Ok(())
    }.await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

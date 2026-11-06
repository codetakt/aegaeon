use super::*;
use crate::{config::RuntimeStateNamespace, stepup::StepUpStore};
use sqlx::{postgres::PgPoolOptions, Executor};
use std::sync::Arc;
use uuid::Uuid;
fn migration() -> &'static str {
    crate::organization_schema::component!("runtime_stepup")
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
        let database = format!("stepup_{}", Uuid::new_v4().simple());
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

    async fn finish(self) -> anyhow::Result<()> {
        self.pool.close().await;
        self.admin
            .execute(format!("DROP DATABASE {}", self.database).as_str())
            .await?;
        self.admin.close().await;
        Ok(())
    }
}

#[test]
fn stepup_binding_is_framed_and_ordered() {
    assert_ne!(binding("a::b", "c", "d"), binding("a", "b::c", "d"));
    assert_ne!(binding("a", "b", "c"), binding("b", "a", "c"));
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; atomic completion, consumption and expiry"]
async fn pg_stepup_bound_atomic_lifecycle() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result=async {
        let namespace=RuntimeStateNamespace::from_environment_id(Uuid::new_v4());
        let store=Arc::new(StepUpStore::from_postgres(fixture.pool.clone(),&namespace,60)?);
        let now=crate::util::now_unix_epoch_secs()?;
        anyhow::ensure!(store.try_issue_challenge_async("client","session","request",u64::MAX).await.map_err(anyhow::Error::msg)?.is_none());
        let first=store.try_issue_challenge_async("client","session","request",now).await.map_err(anyhow::Error::msg)?.ok_or_else(||anyhow::anyhow!("challenge missing"))?;
        anyhow::ensure!(!store.try_consume_completed_async("client","session","request",now).await.map_err(anyhow::Error::msg)?);
        anyhow::ensure!(store.try_complete_for_request_async("client","session","request",now-1).await.map_err(anyhow::Error::msg)?.is_none());
        let foreign=StepUpStore::from_postgres(fixture.pool.clone(),&RuntimeStateNamespace::from_environment_id(Uuid::new_v4()),60)?;
        anyhow::ensure!(foreign.try_complete_for_request_async("client","session","request",now).await.map_err(anyhow::Error::msg)?.is_none());
        for fields in [("other","session","request"),("client","other","request"),("client","session","other")] {
            anyhow::ensure!(store.try_complete_for_request_async(fields.0,fields.1,fields.2,now).await.map_err(anyhow::Error::msg)?.is_none());
        }
        let mut jobs=tokio::task::JoinSet::new();
        for _ in 0..32 { let store=store.clone();jobs.spawn(async move { store.try_complete_for_request_async("client","session","request",now).await }); }
        let mut completed=0;
        while let Some(result)=jobs.join_next().await { if let Some(challenge)=result?.map_err(anyhow::Error::msg)? { anyhow::ensure!(challenge.id==first.id && challenge.completed);completed+=1; } }
        anyhow::ensure!(completed==1);
        let reopened=StepUpStore::from_postgres(fixture.pool.clone(),&namespace,60)?;
        anyhow::ensure!(reopened.try_complete_for_request_async("client","session","request",now).await.map_err(anyhow::Error::msg)?.is_none());
        let mut jobs=tokio::task::JoinSet::new();
        for _ in 0..32 { let store=store.clone();jobs.spawn(async move { store.try_consume_completed_async("client","session","request",now).await }); }
        let mut consumed=0;
        while let Some(result)=jobs.join_next().await { if result?.map_err(anyhow::Error::msg)? { consumed+=1; } }
        anyhow::ensure!(consumed==1);
        anyhow::ensure!(!reopened.try_consume_completed_async("client","session","request",now).await.map_err(anyhow::Error::msg)?);
        for fields in [("a::b","c","d"),("a","b::c","d")] {
            store.try_issue_challenge_async(fields.0,fields.1,fields.2,now).await.map_err(anyhow::Error::msg)?;
        }
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_stepup_challenges").fetch_one(&fixture.pool).await?;
        anyhow::ensure!(count==2);
        let old=store.try_complete_for_request_async("a::b","c","d",now).await.map_err(anyhow::Error::msg)?.ok_or_else(||anyhow::anyhow!("completion missing"))?;
        let replacement=store.try_issue_challenge_async("a::b","c","d",now).await.map_err(anyhow::Error::msg)?.ok_or_else(||anyhow::anyhow!("replacement missing"))?;
        anyhow::ensure!(old.id!=replacement.id && !store.try_consume_completed_async("a::b","c","d",now).await.map_err(anyhow::Error::msg)?);
        sqlx::query("UPDATE aegaeon.runtime_stepup_challenges SET expires_at=clock_timestamp()-interval '1 second'").execute(&fixture.pool).await?;
        anyhow::ensure!(store.try_complete_for_request_async("a::b","c","d",now).await.map_err(anyhow::Error::msg)?.is_none());
        anyhow::ensure!(!store.try_consume_completed_async("a::b","c","d",now).await.map_err(anyhow::Error::msg)?);
        store.cleanup_async().await.map_err(anyhow::Error::msg)?;
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_stepup_challenges").fetch_one(&fixture.pool).await?;
        anyhow::ensure!(count==0);
        sqlx::query("DROP TABLE aegaeon.runtime_stepup_challenges").execute(&fixture.pool).await?;
        anyhow::ensure!(store.try_issue_challenge_async("client","session","request",now).await.is_err());
        anyhow::ensure!(store.try_complete_for_request_async("client","session","request",now).await.is_err());
        anyhow::ensure!(store.try_consume_completed_async("client","session","request",now).await.is_err());
        Ok(())
    }.await;
    fixture.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; expiry after row-lock wait and rollback"]
async fn pg_stepup_lock_wait_rechecks_expiry() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result=async {
        let namespace=RuntimeStateNamespace::from_environment_id(Uuid::new_v4());
        let store=Arc::new(StepUpStore::from_postgres(fixture.pool.clone(),&namespace,60)?);
        let now=crate::util::now_unix_epoch_secs()?;
        store.try_issue_challenge_async("client","session","request",now).await.map_err(anyhow::Error::msg)?;
        anyhow::ensure!(store.try_complete_for_request_async("client","session","request",now).await.map_err(anyhow::Error::msg)?.is_some());
        let mut tx=fixture.pool.begin().await?;
        sqlx::query("DELETE FROM aegaeon.runtime_stepup_challenges").execute(&mut *tx).await?;
        tx.rollback().await?;
        sqlx::query("UPDATE aegaeon.runtime_stepup_challenges SET expires_at=clock_timestamp()+interval '200 milliseconds'").execute(&fixture.pool).await?;
        let mut tx=fixture.pool.begin().await?;
        sqlx::query("SELECT 1 FROM aegaeon.runtime_stepup_challenges FOR UPDATE").execute(&mut *tx).await?;
        let waiting=store.clone();let job=tokio::spawn(async move { waiting.try_consume_completed_async("client","session","request",now).await });
        tokio::time::sleep(Duration::from_millis(450)).await;
        tx.rollback().await?;
        anyhow::ensure!(!job.await?.map_err(anyhow::Error::msg)?);
        anyhow::ensure!(!store.try_consume_completed_async("client","session","request",now).await.map_err(anyhow::Error::msg)?);
        Ok(())
    }.await;
    fixture.finish().await?;
    result
}

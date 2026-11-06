use super::super::UpstreamLogoutRelayStore;
use super::*;
use crate::config::RuntimeStateNamespace;
use sqlx::{postgres::PgPoolOptions, Executor};
use std::sync::Arc;
use uuid::Uuid;
fn migration() -> &'static str {
    crate::organization_schema::component!("runtime_logout_relays")
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
        let database = format!("relay_{}", Uuid::new_v4().simple());
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

fn value() -> UpstreamLogoutRelayState {
    UpstreamLogoutRelayState {
        incident_id: Some(Uuid::new_v4()),
        downstream_redirect_uri: "https://client.example/signed-out".into(),
        downstream_state: Some("state".into()),
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; durable relay concurrency, collision, expiry and failure"]
async fn pg_logout_relay_atomic_consumption() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result=async {
        let namespace=RuntimeStateNamespace::from_environment_id(Uuid::new_v4());
        let store=Arc::new(UpstreamLogoutRelayStore::from_postgres(fixture.pool.clone(),&namespace,60)?);
        let expected=value();
        store.try_insert_async("token".into(),expected.clone()).await.map_err(anyhow::Error::msg)?;
        anyhow::ensure!(store.try_insert_async("token".into(),value()).await.is_err());
        let other=UpstreamLogoutRelayStore::from_postgres(fixture.pool.clone(),&RuntimeStateNamespace::from_environment_id(Uuid::new_v4()),60)?;
        anyhow::ensure!(other.try_take_async("token".into()).await.map_err(anyhow::Error::msg)?.is_none());
        let mut jobs=tokio::task::JoinSet::new();
        for _ in 0..32 { let store=store.clone(); jobs.spawn(async move { store.try_take_async("token".into()).await }); }
        let mut accepted=0;
        while let Some(result)=jobs.join_next().await {
            if let Some(value)=result?.map_err(anyhow::Error::msg)? { anyhow::ensure!(value==expected); accepted+=1; }
        }
        anyhow::ensure!(accepted==1);
        let reopened=UpstreamLogoutRelayStore::from_postgres(fixture.pool.clone(),&namespace,60)?;
        anyhow::ensure!(reopened.try_take_async("token".into()).await.map_err(anyhow::Error::msg)?.is_none());
        store.try_insert_async("expired".into(),value()).await.map_err(anyhow::Error::msg)?;
        sqlx::query("UPDATE aegaeon.runtime_logout_relays SET expires_at=clock_timestamp()-interval '1 second'").execute(&fixture.pool).await?;
        anyhow::ensure!(store.try_take_async("expired".into()).await.map_err(anyhow::Error::msg)?.is_none());
        store.try_insert_async("cleanup".into(),value()).await.map_err(anyhow::Error::msg)?;
        sqlx::query("UPDATE aegaeon.runtime_logout_relays SET expires_at=clock_timestamp()-interval '1 second'").execute(&fixture.pool).await?;
        store.try_insert_async("live".into(),expected.clone()).await.map_err(anyhow::Error::msg)?;
        store.cleanup_async().await.map_err(anyhow::Error::msg)?;
        anyhow::ensure!(store.try_take_async("cleanup".into()).await.map_err(anyhow::Error::msg)?.is_none());
        anyhow::ensure!(store.try_take_async("live".into()).await.map_err(anyhow::Error::msg)?==Some(expected));
        sqlx::query("DROP TABLE aegaeon.runtime_logout_relays").execute(&fixture.pool).await?;
        anyhow::ensure!(store.try_insert_async("new".into(),value()).await.is_err());
        anyhow::ensure!(store.try_take_async("missing".into()).await.is_err());
        Ok(())
    }.await;
    fixture.finish().await?;
    result
}

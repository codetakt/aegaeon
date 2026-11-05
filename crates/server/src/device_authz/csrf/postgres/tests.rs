use super::super::CsrfTokenStore;
use super::*;
use crate::config::RuntimeStateNamespace;
use sqlx::{postgres::PgPoolOptions, Executor};
use std::sync::Arc;
use uuid::Uuid;
fn migration() -> &'static str {
    crate::organization_schema::component!("runtime_csrf_tokens")
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
        let database = format!("csrf_{}", Uuid::new_v4().simple());
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

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; durable CSRF single-use, expiry, namespace and rollback"]
async fn pg_csrf_atomic_consumption_and_failure() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result=async {
        let namespace=RuntimeStateNamespace::from_environment_id(Uuid::new_v4());
        let store=Arc::new(CsrfTokenStore::from_postgres(fixture.pool.clone(),&namespace,"local-auth"));
        let token=store.clone().try_generate_async().await?;
        let other=Arc::new(CsrfTokenStore::from_postgres(fixture.pool.clone(),&namespace,"device"));
        anyhow::ensure!(!other.try_validate_async(token.clone()).await?);
        let mut jobs=tokio::task::JoinSet::new();
        for _ in 0..32 { let store=store.clone();let token=token.clone();jobs.spawn(async move { store.try_validate_async(token).await }); }
        let mut accepted=0;
        while let Some(result)=jobs.join_next().await { if result?? { accepted+=1; } }
        anyhow::ensure!(accepted==1);
        let reopened=Arc::new(CsrfTokenStore::from_postgres(fixture.pool.clone(),&namespace,"local-auth"));
        anyhow::ensure!(!reopened.clone().try_validate_async(token).await?);
        let token=store.clone().try_generate_async().await?;
        let digest=aegaeon_crypto::hash::sha256_digest(token.as_bytes());
        let mut tx=fixture.pool.begin().await?;
        sqlx::query("DELETE FROM aegaeon.runtime_csrf_tokens WHERE token_digest=$1").bind(digest.as_slice()).execute(&mut *tx).await?;
        tx.rollback().await?;
        anyhow::ensure!(reopened.try_validate_async(token).await?);
        let expired=store.clone().try_generate_async().await?;
        sqlx::query("UPDATE aegaeon.runtime_csrf_tokens SET expires_at=clock_timestamp()-interval '1 second'").execute(&fixture.pool).await?;
        anyhow::ensure!(!store.clone().try_validate_async(expired).await?);
        let expired=store.clone().try_generate_async().await?;
        sqlx::query("UPDATE aegaeon.runtime_csrf_tokens SET expires_at=clock_timestamp()-interval '1 second'").execute(&fixture.pool).await?;
        let live=store.clone().try_generate_async().await?;
        store.clone().cleanup_async().await?;
        anyhow::ensure!(!store.clone().try_validate_async(expired).await?);
        anyhow::ensure!(store.clone().try_validate_async(live).await?);
        sqlx::query("DROP TABLE aegaeon.runtime_csrf_tokens").execute(&fixture.pool).await?;
        anyhow::ensure!(store.clone().try_generate_async().await.is_err());
        anyhow::ensure!(store.try_validate_async("missing".into()).await.is_err());
        Ok(())
    }.await;
    fixture.finish().await?;
    result
}

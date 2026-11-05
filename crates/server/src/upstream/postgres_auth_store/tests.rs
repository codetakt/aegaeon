use super::*;
use crate::config::RuntimeStateNamespace;
use crate::upstream::{tests::make_upstream_auth_request, UpstreamAuthStore};
use sqlx::{postgres::PgPoolOptions, Executor};
use std::sync::Arc;
use uuid::Uuid;
fn migration() -> &'static str {
    crate::organization_schema::component!("runtime_upstream_auth")
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
        let database = format!("upstream_{}", Uuid::new_v4().simple());
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
fn postgres_upstream_expiry_is_exact_to_microseconds() -> anyhow::Result<()> {
    let value = SystemTime::UNIX_EPOCH + Duration::new(42, 123_456_789);
    anyhow::ensure!(
        database_expiry(value).map_err(anyhow::Error::msg)? == "1970-01-01 00:00:42.123456+00"
    );
    anyhow::ensure!(database_expiry(SystemTime::UNIX_EPOCH - Duration::from_secs(1)).is_err());
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; durable browser-bound continuation and atomic consumption"]
async fn pg_upstream_auth_bound_single_use_and_failure() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result=async {
        let namespace=RuntimeStateNamespace::from_environment_id(Uuid::new_v4());
        let store=Arc::new(UpstreamAuthStore::from_postgres(fixture.pool.clone(),&namespace,60)?);
        let mut request=make_upstream_auth_request("state",Duration::from_secs(60));
        request.client_secret=Some("must-not-persist-client-secret".into());
        store.try_insert_async(request.clone()).await.map_err(anyhow::Error::msg)?;
        anyhow::ensure!(store.try_insert_async(request).await.is_err());
        let raw:String=sqlx::query_scalar("SELECT payload FROM aegaeon.runtime_upstream_auth").fetch_one(&fixture.pool).await?;
        let payload:serde_json::Value=serde_json::from_str(&raw)?;
        anyhow::ensure!(!raw.contains("must-not-persist-client-secret") && payload.get("client_secret").is_none());
        let digest=aegaeon_crypto::hash::sha256_hex(b"browser-secret");
        let redirect="https://rp.example/callback";
        for (browser,uri) in [("invalid".into(),redirect),(aegaeon_crypto::hash::sha256_hex(b"other"),redirect),(digest.clone(),"https://other.example/callback")] {
            anyhow::ensure!(store.try_consume_bound_async("state".into(),browser,uri.into()).await.map_err(anyhow::Error::msg)?.is_none());
        }
        let foreign=UpstreamAuthStore::from_postgres(fixture.pool.clone(),&RuntimeStateNamespace::from_environment_id(Uuid::new_v4()),60)?;
        anyhow::ensure!(foreign.try_consume_bound_async("state".into(),digest.clone(),redirect.into()).await.map_err(anyhow::Error::msg)?.is_none());
        let mut jobs=tokio::task::JoinSet::new();
        for _ in 0..32 { let store=store.clone();let digest=digest.clone();jobs.spawn(async move { store.try_consume_bound_async("state".into(),digest,redirect.into()).await }); }
        let mut accepted=0;
        while let Some(result)=jobs.join_next().await {
            if let Some(request)=result?.map_err(anyhow::Error::msg)? {
                anyhow::ensure!(request.state=="state" && request.client_secret.is_none()); accepted+=1;
            }
        }
        anyhow::ensure!(accepted==1);
        let reopened=UpstreamAuthStore::from_postgres(fixture.pool.clone(),&namespace,60)?;
        anyhow::ensure!(reopened.try_consume_bound_async("state".into(),digest.clone(),redirect.into()).await.map_err(anyhow::Error::msg)?.is_none());
        store.try_insert_async(make_upstream_auth_request("expired",Duration::from_secs(60))).await.map_err(anyhow::Error::msg)?;
        sqlx::query("UPDATE aegaeon.runtime_upstream_auth SET expires_at=clock_timestamp()-interval '1 second'").execute(&fixture.pool).await?;
        anyhow::ensure!(store.try_consume_bound_async("expired".into(),digest.clone(),redirect.into()).await.map_err(anyhow::Error::msg)?.is_none());
        store.cleanup_async().await.map_err(anyhow::Error::msg)?;
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_upstream_auth").fetch_one(&fixture.pool).await?;
        anyhow::ensure!(count==0);
        store.try_insert_async(make_upstream_auth_request("malformed",Duration::from_secs(60))).await.map_err(anyhow::Error::msg)?;
        sqlx::query("UPDATE aegaeon.runtime_upstream_auth SET payload='{}'").execute(&fixture.pool).await?;
        anyhow::ensure!(store.try_consume_bound_async("malformed".into(),digest.clone(),redirect.into()).await.is_err());
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_upstream_auth").fetch_one(&fixture.pool).await?;
        anyhow::ensure!(count==1,"invalid snapshots must not be silently consumed");
        sqlx::query("DROP TABLE aegaeon.runtime_upstream_auth").execute(&fixture.pool).await?;
        anyhow::ensure!(store.try_insert_async(make_upstream_auth_request("new",Duration::from_secs(60))).await.is_err());
        anyhow::ensure!(store.try_consume_bound_async("state".into(),digest,redirect.into()).await.is_err());
        Ok(())
    }.await;
    fixture.finish().await?;
    result
}

use super::*;
use crate::authcode::{
    store::TokenStore,
    token::AccessTokenAudiencePolicy,
    types::{AccessToken, BearerTokenMeta, BearerTokenMetaInput},
};
use crate::device_authz::{DeviceCodeStore, DevicePollResult};
use sqlx::{postgres::PgPoolOptions, Executor, PgPool};
use uuid::Uuid;
#[path = "tests/expiry.rs"]
mod expiry;
#[path = "tests/transactions.rs"]
mod transactions;
struct Fixture {
    admin: PgPool,
    pool: PgPool,
    database: PostgresGrantDatabase,
    name: String,
}
impl Fixture {
    async fn new() -> anyhow::Result<Self> {
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?)
            .await?;
        let name = format!("device_state_{}", Uuid::new_v4().simple());
        admin
            .execute(format!("CREATE DATABASE {name}").as_str())
            .await?;
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .connect_with(admin.connect_options().as_ref().clone().database(&name))
            .await?;
        pool.execute("CREATE SCHEMA aegaeon").await?;
        for sql in [
            crate::organization_schema::component!("runtime_token_grants"),
            crate::organization_schema::component!("runtime_device_codes"),
        ] {
            sqlx::raw_sql(sql).execute(&pool).await?;
        }
        let database = PostgresGrantDatabase::new(
            pool.clone(),
            &crate::config::RuntimeStateNamespace::from_environment_id(Uuid::new_v4()),
        );
        Ok(Self {
            admin,
            pool,
            database,
            name,
        })
    }
    fn devices(&self, ttl: u64) -> anyhow::Result<DeviceCodeStore> {
        Ok(DeviceCodeStore::from_postgres(
            self.database.clone(),
            ttl,
            5,
        )?)
    }
    fn tokens(&self) -> TokenStore {
        TokenStore::from_postgres(self.database.clone())
    }
    async fn create(
        &self,
        ttl: u64,
        resource: Option<&str>,
    ) -> anyhow::Result<(
        DeviceCodeStore,
        crate::device_authz::DeviceAuthorizationResponse,
    )> {
        let store = self.devices(ttl)?;
        let code = store
            .try_create_with_resource_async(
                "client".into(),
                Some("read".into()),
                resource.map(str::to_string),
                None,
                "https://issuer.example/device".into(),
            )
            .await
            .ok_or_else(|| anyhow::anyhow!("code missing"))?;
        Ok((store, code))
    }
    async fn prepare(
        &self,
        store: &DeviceCodeStore,
        code: &crate::device_authz::DeviceAuthorizationResponse,
    ) -> anyhow::Result<PostgresDeviceGrantCommit> {
        anyhow::ensure!(store
            .try_approve_async(code.user_code.clone(), "subject".into())
            .await
            .map_err(anyhow::Error::msg)?);
        let (result, commit) = store
            .prepare_token_grant_async(
                code.device_code.clone(),
                "client".into(),
                None,
                None,
                AccessTokenAudiencePolicy::new(false, None),
            )
            .await
            .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(matches!(result, DevicePollResult::Approved { .. }));
        commit.ok_or_else(|| anyhow::anyhow!("commit missing"))
    }
    async fn count(&self) -> anyhow::Result<(i64, i64)> {
        Ok(sqlx::query_as("SELECT (SELECT count(*) FROM aegaeon.runtime_device_codes),(SELECT count(*) FROM aegaeon.runtime_token_capabilities)").fetch_one(&self.pool).await?)
    }
    async fn finish(self) -> anyhow::Result<()> {
        self.pool.close().await;
        self.admin
            .execute(format!("DROP DATABASE {}", self.name).as_str())
            .await?;
        self.admin.close().await;
        Ok(())
    }
}
fn grant() -> (AccessToken, BearerTokenMeta) {
    let a = AccessToken::new("client".into(), "subject".into(), Some("read".into()), 300);
    let m = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: a.token.clone(),
        client_id: a.client_id.clone(),
        user_id: a.user_id.clone(),
        granted_scopes: vec!["read".into()],
        audience: "client".into(),
        sender_binding: None,
        authorization_details: None,
        auth_time_epoch_secs: None,
        acr: None,
        issued_at: a.created_at,
        expires_at: a.created_at + Duration::from_secs(300),
        refresh_parent: None,
    });
    (a, m)
}

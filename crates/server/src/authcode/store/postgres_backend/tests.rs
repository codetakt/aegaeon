use super::super::grant_commit::AuthorizationCodeGrantCommit;
use super::*;
use crate::authcode::store::{AuthCodeStore, TokenStore};
use crate::authcode::types::{
    AuthorizationCode, AuthorizationCodeInput, BearerTokenMetaInput, RefreshTokenInput,
};
use crate::oidc::{OidcSessionContext, OidcSessionStore};
use sqlx::{postgres::PgPoolOptions, Executor, PgPool};
use uuid::Uuid;

#[path = "tests/cleanup.rs"]
mod cleanup_tests;
#[path = "tests/exchange.rs"]
mod exchange_tests;
#[path = "tests/expiry.rs"]
mod expiry_tests;
#[path = "tests/inventory.rs"]
mod inventory_tests;
#[path = "tests/revocation.rs"]
mod revocation_tests;
#[path = "tests/rotation.rs"]
mod rotation_tests;

struct Fixture {
    admin: PgPool,
    pool: PgPool,
    name: String,
    database: PostgresGrantDatabase,
}
impl Fixture {
    async fn new() -> anyhow::Result<Self> {
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?)
            .await?;
        let name = format!("token_state_{}", Uuid::new_v4().simple());
        admin
            .execute(format!("CREATE DATABASE {name}").as_str())
            .await?;
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(admin.connect_options().as_ref().clone().database(&name))
            .await?;
        pool.execute("CREATE SCHEMA aegaeon").await?;
        for sql in [
            crate::organization_schema::component!("runtime_par"),
            crate::organization_schema::component!("runtime_authorization_codes"),
            crate::organization_schema::component!("runtime_oidc_sessions"),
            crate::organization_schema::component!("runtime_token_grants"),
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
            name,
            database,
        })
    }
    fn store(&self) -> TokenStore {
        TokenStore::from_postgres(self.database.clone())
    }
    fn codes(&self) -> anyhow::Result<AuthCodeStore> {
        AuthCodeStore::from_postgres(self.database.clone(), Duration::from_secs(60))
            .map_err(anyhow::Error::msg)
    }
    fn oidc(&self) -> anyhow::Result<OidcSessionStore> {
        Ok(OidcSessionStore::from_postgres(60, self.database.clone())?)
    }
    async fn code(&self) -> anyhow::Result<(AuthorizationCode, String)> {
        let mut input = AuthorizationCodeInput::new("client".into(), "subject".into(), None);
        input.auth_session_id = Some("browser".into());
        let code = AuthorizationCode::new(input);
        let codes = self.codes()?;
        codes
            .store_code_async(code.clone())
            .await
            .map_err(anyhow::Error::msg)?;
        let stored = codes
            .try_get_code_for_exchange_async(code.code.clone())
            .await
            .map_err(anyhow::Error::msg)?
            .ok_or_else(|| anyhow::anyhow!("code missing"))?;
        Ok(stored.into_parts())
    }
    async fn counts(&self) -> anyhow::Result<(i64, i64, i64, i64)> {
        Ok(sqlx::query_as("SELECT (SELECT count(*) FROM aegaeon.runtime_token_capabilities),(SELECT count(*) FROM aegaeon.runtime_refresh_families),(SELECT count(*) FROM aegaeon.runtime_oidc_sessions),(SELECT count(*) FROM aegaeon.runtime_authorization_codes)").fetch_one(&self.pool).await?)
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

fn grant(with_refresh: bool) -> (AccessToken, Option<RefreshToken>, BearerTokenMeta) {
    let access = AccessToken::new("client".into(), "subject".into(), Some("read".into()), 300);
    let refresh = with_refresh.then(|| {
        let mut input = RefreshTokenInput::new("client".into(), "subject".into());
        input.scope = Some("read".into());
        RefreshToken::with_ttl(input, 600)
    });
    let meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: access.token.clone(),
        client_id: access.client_id.clone(),
        user_id: access.user_id.clone(),
        granted_scopes: vec!["read".into()],
        audience: "client".into(),
        sender_binding: None,
        authorization_details: None,
        auth_time_epoch_secs: None,
        acr: None,
        issued_at: access.created_at,
        expires_at: access.created_at + Duration::from_secs(300),
        refresh_parent: refresh.as_ref().map(|r| r.token.clone()),
    });
    (access, refresh, meta)
}

#[tokio::test]
#[ignore = "requires PostgreSQL; single-use code with tokens/family/OIDC in one transaction"]
async fn pg_token_code_redemption_concurrent_atomic_grant() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let (code, payload) = fixture.code().await?;
        let oidc = fixture.oidc()?;
        let prepared = oidc
            .prepare_authorization_code_grant_commit_async(
                OidcSessionContext {
                    user_id: "subject",
                    auth_session_id: "browser",
                },
                "client",
            )
            .await
            .map_err(anyhow::Error::msg)?;
        let sid = prepared.sid().to_owned();
        let mut jobs = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let (a, r, m) = grant(true);
            let commit = AuthorizationCodeGrantCommit::new(
                fixture.codes()?,
                code.code.clone(),
                payload.clone(),
                a,
                r,
                m,
                Some(prepared.clone()),
            );
            let store = fixture.store();
            jobs.spawn(async move {
                store
                    .store_issued_authorization_code_grant_async(commit)
                    .await
            });
        }
        let mut successes = Vec::new();
        let mut refusals = 0;
        while let Some(result) = jobs.join_next().await {
            match result? {
                Ok(value) => successes.push(value),
                Err(error)
                    if error
                        == super::super::grant_commit::AUTHORIZATION_CODE_GRANT_CODE_MISSING =>
                {
                    refusals += 1
                }
                Err(error) => anyhow::bail!(error),
            }
        }
        anyhow::ensure!(successes.len() == 1 && refusals == 31);
        anyhow::ensure!(fixture.counts().await? == (2, 1, 1, 0));
        let (access, refresh) = successes.remove(0);
        let store = fixture.store();
        anyhow::ensure!(store
            .try_verify_access_token_async(access.clone())
            .await
            .map_err(anyhow::Error::msg)?
            .is_some());
        anyhow::ensure!(store
            .try_get_bearer_meta_async(access)
            .await
            .map_err(anyhow::Error::msg)?
            .is_some());
        anyhow::ensure!(store
            .try_get_refresh_token_async(refresh.ok_or_else(|| anyhow::anyhow!("refresh missing"))?)
            .await
            .map_err(anyhow::Error::msg)?
            .is_some());
        let event = oidc
            .try_logout_by_sid_async(sid)
            .await
            .map_err(anyhow::Error::msg)?
            .ok_or_else(|| anyhow::anyhow!("OIDC binding missing"))?;
        anyhow::ensure!(event.client_ids == ["client"]);
        Ok(())
    }
    .await;
    fixture.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires PostgreSQL; mismatch/collision/OIDC conflict roll back every grant row"]
async fn pg_token_code_redemption_rollback_and_binding() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let (code, payload) = fixture.code().await?;
        let store = fixture.store();
        let (a, r, m) = grant(true);
        let commit = AuthorizationCodeGrantCommit::new(
            fixture.codes()?,
            code.code.clone(),
            format!("{payload} "),
            a,
            r,
            m,
            None,
        );
        anyhow::ensure!(store
            .store_issued_authorization_code_grant_async(commit)
            .await
            .is_err());
        anyhow::ensure!(fixture.counts().await? == (0, 0, 0, 1));
        let (a, r, m) = grant(true);
        let other = PostgresGrantDatabase::new(
            fixture.pool.clone(),
            &crate::config::RuntimeStateNamespace::from_environment_id(Uuid::new_v4()),
        );
        let commit = AuthorizationCodeGrantCommit::new(
            AuthCodeStore::from_postgres(other, Duration::from_secs(60))
                .map_err(anyhow::Error::msg)?,
            code.code.clone(),
            payload.clone(),
            a,
            r,
            m,
            None,
        );
        anyhow::ensure!(store
            .store_issued_authorization_code_grant_async(commit)
            .await
            .is_err());
        anyhow::ensure!(fixture.counts().await? == (0, 0, 0, 1));
        let oidc = fixture.oidc()?;
        let context = OidcSessionContext {
            user_id: "subject",
            auth_session_id: "browser",
        };
        let stale = oidc
            .prepare_authorization_code_grant_commit_async(context, "client")
            .await
            .map_err(anyhow::Error::msg)?;
        oidc.try_get_or_create_session_async(context)
            .await
            .map_err(anyhow::Error::msg)?;
        let (a, r, m) = grant(true);
        let commit = AuthorizationCodeGrantCommit::new(
            fixture.codes()?,
            code.code.clone(),
            payload.clone(),
            a,
            r,
            m,
            Some(stale),
        );
        anyhow::ensure!(store
            .store_issued_authorization_code_grant_async(commit)
            .await
            .is_err());
        anyhow::ensure!(fixture.counts().await? == (0, 0, 1, 1));
        let (a, r, m) = grant(true);
        let duplicate = a.clone();
        let duplicate_meta = m.clone();
        store
            .store_issued_grant_async(a, r, m)
            .await
            .map_err(anyhow::Error::msg)?;
        let (_, r, _) = grant(true);
        let mut m = duplicate_meta;
        m.refresh_parent = r.as_ref().map(|r| r.token.clone());
        let commit = AuthorizationCodeGrantCommit::new(
            fixture.codes()?,
            code.code,
            payload,
            duplicate,
            r,
            m,
            None,
        );
        anyhow::ensure!(store
            .store_issued_authorization_code_grant_async(commit)
            .await
            .is_err());
        anyhow::ensure!(fixture.counts().await? == (2, 1, 1, 1));
        Ok(())
    }
    .await;
    fixture.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires PostgreSQL; missing/revoked family and damaged bound capability deny authority"]
async fn pg_token_current_authority_missing_revoked_and_corrupt() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let store = fixture.store();
        let (a, r, m) = grant(true);
        let (access, refresh) = store
            .store_issued_grant_async(a, r, m)
            .await
            .map_err(anyhow::Error::msg)?;
        sqlx::query("UPDATE aegaeon.runtime_refresh_families SET revoked=true")
            .execute(&fixture.pool)
            .await?;
        anyhow::ensure!(store
            .try_verify_access_token_async(access.clone())
            .await
            .map_err(anyhow::Error::msg)?
            .is_none());
        sqlx::query("UPDATE aegaeon.runtime_refresh_families SET revoked=false")
            .execute(&fixture.pool)
            .await?;
        anyhow::ensure!(store
            .try_verify_access_token_async(access.clone())
            .await
            .map_err(anyhow::Error::msg)?
            .is_some());
        let mut tx = fixture.pool.begin().await?;
        sqlx::query("SET LOCAL session_replication_role='replica'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM aegaeon.runtime_refresh_families")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        anyhow::ensure!(store
            .try_verify_access_token_async(access.clone())
            .await
            .map_err(anyhow::Error::msg)?
            .is_none());
        anyhow::ensure!(store
            .try_get_refresh_token_async(refresh.ok_or_else(|| anyhow::anyhow!("refresh missing"))?)
            .await
            .map_err(anyhow::Error::msg)?
            .is_none());
        sqlx::query(
            "UPDATE aegaeon.runtime_token_capabilities SET client_digest=sha256('wrong'::bytea)",
        )
        .execute(&fixture.pool)
        .await?;
        anyhow::ensure!(store
            .try_verify_access_token_async(access.clone())
            .await
            .is_err());
        sqlx::query("DROP TABLE aegaeon.runtime_token_capabilities")
            .execute(&fixture.pool)
            .await?;
        anyhow::ensure!(store.try_verify_access_token_async(access).await.is_err());
        Ok(())
    }
    .await;
    fixture.finish().await?;
    result
}

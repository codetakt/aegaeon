use super::*;
use sqlx::{postgres::PgPoolOptions, Executor};
use std::{collections::HashSet, sync::Arc};
use uuid::Uuid;
fn migration() -> &'static str {
    crate::organization_schema::component!("runtime_dpop_nonces")
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
        let database = format!("nonce_{}", Uuid::new_v4().simple());
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
#[ignore = "requires isolated PostgreSQL; shared nonce rotation and read-only validation"]
async fn pg_dpop_nonce_concurrency_rotation_and_cleanup() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let store = Arc::new(PostgresDpopNonceStore::new(fixture.pool.clone(), "a".into()));
        let role = DpopEndpointRole::AuthorizationServer;
        let mut jobs = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let store = store.clone();
            jobs.spawn(async move { store.issue(role, Duration::from_secs(60)).await });
        }
        let mut issued = HashSet::new();
        while let Some(value) = jobs.join_next().await {
            issued.insert(value?.map_err(|err| anyhow::anyhow!("{err:?}"))?);
        }
        anyhow::ensure!(issued.len()==1);
        let old = issued.into_iter().next().ok_or_else(|| anyhow::anyhow!("missing nonce"))?;
        anyhow::ensure!(store.validate(role,&old).await.map_err(|e| anyhow::anyhow!("{e:?}"))?);
        anyhow::ensure!(!store.validate(DpopEndpointRole::ResourceServer,&old).await.map_err(|e| anyhow::anyhow!("{e:?}"))?);
        let foreign = PostgresDpopNonceStore::new(fixture.pool.clone(), "b".into());
        anyhow::ensure!(!foreign.validate(role,&old).await.map_err(|e| anyhow::anyhow!("{e:?}"))?);
        let reopened = PostgresDpopNonceStore::new(fixture.pool.clone(), "a".into());
        anyhow::ensure!(reopened.validate(role,&old).await.map_err(|e| anyhow::anyhow!("{e:?}"))?);
        // Validation neither waits for the row writer nor changes/extends a record.
        let mut lock = fixture.pool.begin().await?;
        sqlx::query("SELECT FROM aegaeon.runtime_dpop_nonces WHERE namespace='a' FOR UPDATE").execute(&mut *lock).await?;
        anyhow::ensure!(tokio::time::timeout(Duration::from_secs(2),store.validate(role,&old)).await?.map_err(|e| anyhow::anyhow!("{e:?}"))?);
        lock.rollback().await?;
        let before: String = sqlx::query_scalar("SELECT row_to_json(n)::text FROM aegaeon.runtime_dpop_nonces n WHERE namespace='a'").fetch_one(&fixture.pool).await?;
        // Deliberately malformed public proof input, never an accepted credential.
        anyhow::ensure!(!store.validate(role,"invalid").await.map_err(|e| anyhow::anyhow!("{e:?}"))?);
        let after: String = sqlx::query_scalar("SELECT row_to_json(n)::text FROM aegaeon.runtime_dpop_nonces n WHERE namespace='a'").fetch_one(&fixture.pool).await?;
        anyhow::ensure!(before==after);
        sqlx::query("UPDATE aegaeon.runtime_dpop_nonces SET rotate_at=clock_timestamp()-interval '1 second' WHERE namespace='a'").execute(&fixture.pool).await?;
        let fresh=store.issue(role,Duration::from_secs(60)).await.map_err(|e| anyhow::anyhow!("{e:?}"))?;
        anyhow::ensure!(old!=fresh);
        anyhow::ensure!(store.validate(role,&old).await.map_err(|e| anyhow::anyhow!("{e:?}"))?);
        sqlx::query("UPDATE aegaeon.runtime_dpop_nonces SET previous_until=clock_timestamp()-interval '1 second' WHERE namespace='a'").execute(&fixture.pool).await?;
        anyhow::ensure!(!store.validate(role,&old).await.map_err(|e| anyhow::anyhow!("{e:?}"))?);
        anyhow::ensure!(store.validate(role,&fresh).await.map_err(|e| anyhow::anyhow!("{e:?}"))?);
        sqlx::query("UPDATE aegaeon.runtime_dpop_nonces SET rotate_at=clock_timestamp()-interval '2 seconds',expires_at=clock_timestamp()-interval '1 second' WHERE namespace='a'").execute(&fixture.pool).await?;
        anyhow::ensure!(!store.validate(role,&fresh).await.map_err(|e| anyhow::anyhow!("{e:?}"))?);
        store.cleanup().await.map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let count: i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_dpop_nonces").fetch_one(&fixture.pool).await?;
        anyhow::ensure!(count==0);
        anyhow::ensure!(!store.validate(role,&old).await.map_err(|e| anyhow::anyhow!("{e:?}"))?);
        anyhow::ensure!(store.issue(role,Duration::MAX).await.is_err());
        sqlx::query("DROP FUNCTION aegaeon.issue_runtime_dpop_nonce(text,text,text,bigint)").execute(&fixture.pool).await?;
        anyhow::ensure!(store.issue(role,Duration::from_secs(60)).await.is_err());
        sqlx::query("DROP TABLE aegaeon.runtime_dpop_nonces").execute(&fixture.pool).await?;
        anyhow::ensure!(store.validate(role,&old).await.is_err());
        Ok(())
    }.await;
    fixture.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; nonce challenge before durable replay of a native proof"]
async fn pg_dpop_nonce_native_proof_before_replay() -> anyhow::Result<()> {
    use crate::middleware::dpop::DpopMiddleware;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let fixture = Fixture::new().await?;
    let result = async {
        sqlx::raw_sql(crate::organization_schema::component!("runtime_replay")).execute(&fixture.pool).await?;
        let nonce_store=Arc::new(DpopNonceStore::from_postgres(fixture.pool.clone(),"nonce-native".into(),Duration::from_secs(60)));
        let middleware=DpopMiddleware::from_postgres(fixture.pool.clone(),"native".into(),"https://issuer.example".into(),Duration::from_secs(601))
            .with_native_verifier_for_tests().with_nonce_store(nonce_store);
        let material=aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let key=aegaeon_crypto::signing::Ed25519SigningKey::from_pkcs8(&material.pkcs8)?;
        let header=serde_json::json!({"typ":"dpop+jwt","alg":"EdDSA","jwk":{"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(&material.public_key)}});
        let proof=|nonce:Option<&str>| -> anyhow::Result<String> {
            let claims=serde_json::json!({"htm":"POST","htu":"https://issuer.example/token","iat":crate::util::now_unix_epoch_secs()?,"jti":"nonce-native","nonce":nonce});
            let input=format!("{}.{}",URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?));
            Ok(format!("{input}.{}",URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes())?)))
        };
        let pending=|proof: &str| middleware.prepare_components_for(DpopEndpointRole::AuthorizationServer,&http::Method::POST,&http::Uri::from_static("/token"),proof,None)
            .map_err(|err| anyhow::anyhow!("{err:?}"));
        let nonce=match pending(&proof(None)?)?.finish_async().await {
            Err(DpopError::UseDpopNonce(nonce)) => nonce,
            other => anyhow::bail!("missing nonce did not challenge: {other:?}"),
        };
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_replay_entries").fetch_one(&fixture.pool).await?;
        anyhow::ensure!(count==0,"a nonce challenge must not consume proof replay identity");
        let signed=proof(Some(&nonce))?;
        anyhow::ensure!(pending(&signed)?.finish_async().await.is_ok());
        anyhow::ensure!(matches!(pending(&signed)?.finish_async().await,Err(DpopError::Replay)));
        Ok(())
    }.await;
    fixture.finish().await?;
    result
}

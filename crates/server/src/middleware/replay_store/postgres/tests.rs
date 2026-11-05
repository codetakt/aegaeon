use super::*;
use sqlx::{postgres::PgPoolOptions, Executor};
use std::sync::Arc;
use uuid::Uuid;

fn migration() -> &'static str {
    crate::organization_schema::component!("runtime_replay")
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
        let database = format!("replay_{}", Uuid::new_v4().simple());
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

fn entry(namespace: &str, material: &[u8]) -> OwnedReplayEntry {
    OwnedReplayEntry::new(namespace.into(), material.to_vec(), Duration::from_secs(60))
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; concurrent durable replay admission"]
async fn pg_replay_atomic_concurrency_and_namespace() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let store = Arc::new(PostgresReplayStore::new(
            fixture.pool.clone(),
            "environment-a".into(),
        ));
        let mut jobs = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let store = store.clone();
            jobs.spawn(async move { store.check_and_store_async(entry("dpop", b"proof")).await });
        }
        let mut accepted = 0;
        let mut replayed = 0;
        while let Some(result) = jobs.join_next().await {
            match result? {
                Ok(()) => accepted += 1,
                Err(ReplayStoreError::Replay) => replayed += 1,
                Err(error) => return Err(error.into()),
            }
        }
        anyhow::ensure!((accepted, replayed) == (1, 31));
        let reopened = Arc::new(PostgresReplayStore::new(
            fixture.pool.clone(),
            "environment-a".into(),
        ));
        anyhow::ensure!(matches!(
            reopened
                .check_and_store_async(entry("dpop", b"proof"))
                .await,
            Err(ReplayStoreError::Replay)
        ));
        store
            .clone()
            .check_and_store_async(entry("assertion", b"proof"))
            .await?;
        Arc::new(PostgresReplayStore::new(
            fixture.pool.clone(),
            "environment-b".into(),
        ))
        .check_and_store_async(entry("dpop", b"proof"))
        .await?;
        anyhow::ensure!(store
            .check_and_store(ReplayEntry::new("dpop", b"unused", Duration::from_secs(1)))
            .is_err());
        Ok(())
    }
    .await;
    fixture.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; replay expiry cleanup and fail-closed backend"]
async fn pg_replay_expiry_cleanup_and_failure() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let store = Arc::new(PostgresReplayStore::new(fixture.pool.clone(), "expiry".into()));
        store.clone().check_and_store_async(entry("dpop", b"proof")).await?;
        sqlx::query("UPDATE aegaeon.runtime_replay_entries SET expires_at=clock_timestamp()-interval '1 second'")
            .execute(&fixture.pool).await?;
        store.clone().check_and_store_async(entry("dpop", b"proof")).await?;
        sqlx::query("INSERT INTO aegaeon.runtime_replay_entries SELECT 'expiry',lpad(n::text,43,'0'),clock_timestamp()-interval '1 second' FROM generate_series(1,8193) n")
            .execute(&fixture.pool).await?;
        sqlx::query("INSERT INTO aegaeon.runtime_replay_entries VALUES ('other',repeat('a',43),clock_timestamp()-interval '1 second')")
            .execute(&fixture.pool).await?;
        let mut locked = fixture.pool.begin().await?;
        sqlx::query("SELECT token_digest FROM aegaeon.runtime_replay_entries WHERE namespace='expiry' AND expires_at<clock_timestamp() ORDER BY expires_at LIMIT 1 FOR UPDATE")
            .execute(&mut *locked).await?;
        let progress = crate::runtime_security_cleanup::cleanup(&fixture.pool, "expiry", crate::runtime_security_cleanup::Kind::Replay, 1)
            .await.map_err(anyhow::Error::msg)?;
        anyhow::ensure!(progress.removed == 4096 && progress.more);
        let progress = crate::runtime_security_cleanup::cleanup(&fixture.pool, "expiry", crate::runtime_security_cleanup::Kind::Replay, crate::runtime_security_cleanup::PASS_BATCHES)
            .await.map_err(anyhow::Error::msg)?;
        anyhow::ensure!(progress.removed == 4096 && progress.more, "locked expired row must remain visible as backlog after a short batch");
        locked.rollback().await?;
        store.clone().cleanup_async().await?;
        let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_replay_entries").fetch_one(&fixture.pool).await?;
        anyhow::ensure!(remaining == 2, "cleanup must retain the live decision and the other namespace");
        anyhow::ensure!(matches!(store.clone().check_and_store_async(entry("dpop", b"proof")).await, Err(ReplayStoreError::Replay)));
        anyhow::ensure!(matches!(store.clone().check_and_store_async(OwnedReplayEntry::new("dpop".into(), vec![1], Duration::MAX)).await, Err(ReplayStoreError::RetentionOverflow)));
        sqlx::query("DROP FUNCTION aegaeon.record_runtime_replay(text,text,bigint)").execute(&fixture.pool).await?;
        anyhow::ensure!(matches!(store.check_and_store_async(entry("dpop", b"new")).await, Err(ReplayStoreError::BackendUnavailable(_))));
        Ok(())
    }.await;
    fixture.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; replay commit and rollback"]
async fn pg_replay_transaction_outcomes() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let key = entry("dpop", b"proof").borrowed().encoded_digest();
        let mut tx = fixture.pool.begin().await?;
        let accepted: bool =
            sqlx::query_scalar("SELECT aegaeon.record_runtime_replay('test',$1,60000)")
                .bind(&key)
                .fetch_one(&mut *tx)
                .await?;
        anyhow::ensure!(accepted);
        tx.rollback().await?;
        let store = Arc::new(PostgresReplayStore::new(
            fixture.pool.clone(),
            "test".into(),
        ));
        store
            .clone()
            .check_and_store_async(entry("dpop", b"proof"))
            .await?;
        anyhow::ensure!(matches!(
            store.check_and_store_async(entry("dpop", b"proof")).await,
            Err(ReplayStoreError::Replay)
        ));
        for invalid in [
            "NULL, NULL, NULL",
            "'test', 'short', 1",
            "'test', repeat('a',43), 0",
            "'', repeat('a',43), 1",
        ] {
            anyhow::ensure!(sqlx::query(&format!(
                "SELECT aegaeon.record_runtime_replay({invalid})"
            ))
            .execute(&fixture.pool)
            .await
            .is_err());
        }
        Ok(())
    }
    .await;
    fixture.finish().await?;
    result
}

use crate::organizations::witness::tests::caller_fixture::CallerFixture;
#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; durable replay retains admitted work after caller cancellation"]
async fn shared_redis_organizations_durable_replay_retains_cancelled_caller() -> anyhow::Result<()>
{
    let database = crate::dcr_persistence::test_database::Database::create(false).await?;
    let environment = uuid::Uuid::new_v4();
    let witness = CallerFixture::with_test_stores(
        environment,
        database.pool.connect_options().as_ref().clone(),
    )
    .await?;
    let namespace = format!("cancelled-replay-{environment}");
    let store = Arc::new(PostgresReplayStore::new(
        database.pool.clone(),
        namespace.clone(),
    ));
    let result = async {
        let mut barrier = database.admin.begin().await?;
        sqlx::query("LOCK TABLE aegaeon.runtime_replay_entries IN ACCESS EXCLUSIVE MODE").execute(&mut *barrier).await?;
        let work = witness.begin().await?;
        let store = store.clone();
        let caller = tokio::spawn(async move {
            work.execute(async move { store.check_and_store_async(entry("dpop", b"cancelled")).await }).await
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%record_runtime_replay%')")
                    .fetch_one(&database.admin).await?;
                if waiting { break Ok::<_, sqlx::Error>(()); }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await??;
        caller.abort();
        anyhow::ensure!(caller.await.unwrap_err().is_cancelled());
        barrier.rollback().await?;
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if witness.pending().await? == 0 { break Ok::<_, anyhow::Error>(()); }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await??;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_replay_entries WHERE namespace=$1")
            .bind(&namespace).fetch_one(&database.pool).await?;
        anyhow::ensure!(count == 1, "cancelled caller must retain exactly one committed replay record");
        Ok(())
    }.await;
    let cleanup = witness.finish().await;
    database.cleanup().await?;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; native Ed25519 proof and durable replay decision"]
async fn pg_replay_native_dpop_verification() -> anyhow::Result<()> {
    use crate::middleware::{dpop::DpopEndpointRole, DpopError, DpopMiddleware};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let fixture = Fixture::new().await?;
    let result = async {
        let material = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let key = aegaeon_crypto::signing::Ed25519SigningKey::from_pkcs8(&material.pkcs8)?;
        let header = serde_json::json!({"typ":"dpop+jwt","alg":"EdDSA","jwk":{"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(&material.public_key)}});
        let claims = serde_json::json!({"htm":"POST","htu":"https://issuer.example/token","iat":crate::util::now_unix_epoch_secs()?,"jti":"native-replay"});
        let input = format!("{}.{}", URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?), URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?));
        let proof = format!("{input}.{}", URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes())?));
        let uri = http::Uri::from_static("/token");
        for duplicate in [false, true] {
            let middleware = DpopMiddleware::from_postgres(fixture.pool.clone(), "native".into(), "https://issuer.example".into(), Duration::from_secs(601)).with_native_verifier_for_tests();
            let pending = middleware.prepare_components_for(DpopEndpointRole::AuthorizationServer, &http::Method::POST, &uri, &proof, None)
                .map_err(|err| anyhow::anyhow!("valid native proof failed: {err:?}"))?;
            let result = pending.finish_async().await;
            if duplicate { anyhow::ensure!(matches!(result, Err(DpopError::Replay))); }
            else { anyhow::ensure!(result.is_ok()); }
            anyhow::ensure!(matches!(middleware.prepare_components_for(DpopEndpointRole::AuthorizationServer, &http::Method::GET, &uri, &proof, None), Err(DpopError::InvalidProof)));
        }
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_replay_entries").fetch_one(&fixture.pool).await?;
        anyhow::ensure!(count == 1);
        Ok(())
    }.await;
    fixture.finish().await?;
    result
}

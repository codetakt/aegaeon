use super::*;
use sqlx::{postgres::PgPoolOptions, Executor, PgPool};
use std::sync::Arc;
use uuid::Uuid;
mod publication;
fn migration() -> &'static str {
    crate::organization_schema::component!("runtime_par")
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
        let database = format!("par_state_{}", Uuid::new_v4().simple());
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
        sqlx::raw_sql(crate::organization_schema::component!(
            "runtime_authorization_codes"
        ))
        .execute(&pool)
        .await?;
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

fn grant_database(pool: PgPool) -> PostgresGrantDatabase {
    PostgresGrantDatabase::new(
        pool,
        &crate::config::RuntimeStateNamespace::from_environment_id(Uuid::new_v4()),
    )
}
fn stored() -> anyhow::Result<StoredParRequest> {
    let mut request: crate::par::ParRequest = serde_json::from_value(serde_json::json!({
        "client_id":"par-client","redirect_uri":"https://client.example/cb","response_type":"code",
        "response_mode":"form_post","state":"state-sentinel","client_secret":"par-secret-sentinel",
        "client_authenticated":true,"code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256","dpop_jkt":null
    }))?;
    request.client_secret = Some("par-secret-sentinel".into());
    Ok(StoredParRequest {
        request,
        client_id: "par-client".into(),
        expires_at: SystemTime::now() + Duration::from_secs(60),
        authorize_continuation: None,
    })
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; PAR reservation/consumption races, binding and confidentiality"]
async fn pg_par_shared_reservation_consume_and_binding() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let database = grant_database(fixture.pool.clone());
        let backend = Arc::new(PostgresParRequestStore::new(database.clone()));
        let other = PostgresParRequestStore::new(database.clone());
        anyhow::ensure!(database.same_database(&database.clone()));
        anyhow::ensure!(!database.same_database(&PostgresGrantDatabase::new(
            fixture.pool.clone(),
            &crate::config::RuntimeStateNamespace::from_environment_id(Uuid::new_v4())
        )));
        let uri = crate::par::ParStore::generate_request_uri();
        backend.insert(&uri, stored()?).await?;
        let record = other
            .load(&uri)
            .await?
            .ok_or_else(|| anyhow::anyhow!("PAR missing"))?;
        anyhow::ensure!(
            record.request.client_secret.is_none()
                && record.request.state.as_deref() == Some("state-sentinel")
        );
        let raw: String = sqlx::query_scalar("SELECT payload FROM aegaeon.runtime_par_requests")
            .fetch_one(&fixture.pool)
            .await?;
        anyhow::ensure!(!raw.contains("par-secret-sentinel"));
        anyhow::ensure!(backend.insert(&uri, stored()?).await.is_err());
        anyhow::ensure!(matches!(
            backend
                .reserve(&uri, "wrong-client", &"a".repeat(43))
                .await?,
            Lookup::ClientMismatch
        ));
        anyhow::ensure!(backend
            .load(&uri)
            .await?
            .is_some_and(|row| row.authorize_continuation.is_none()));
        let foreign = PostgresParRequestStore::new(grant_database(fixture.pool.clone()));
        anyhow::ensure!(foreign.load(&uri).await?.is_none());
        let mut jobs = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let backend = backend.clone();
            let uri = uri.clone();
            jobs.spawn(async move {
                backend
                    .reserve(
                        &uri,
                        "par-client",
                        &crate::par::ParStore::generate_authorize_continuation(),
                    )
                    .await
            });
        }
        let mut winners = 0;
        while let Some(result) = jobs.join_next().await {
            match result?? {
                Lookup::Found(_) => winners += 1,
                Lookup::Missing => {}
                Lookup::ClientMismatch => anyhow::bail!("unexpected client mismatch"),
            }
        }
        anyhow::ensure!(winners == 1);
        let reserved = other
            .load(&uri)
            .await?
            .ok_or_else(|| anyhow::anyhow!("reserved PAR missing"))?;
        let continuation = reserved
            .authorize_continuation
            .ok_or_else(|| anyhow::anyhow!("continuation missing"))?;
        let store = Arc::new(crate::par::ParStore::from_postgres(60, database.clone())?);
        anyhow::ensure!(store
            .clone()
            .resume_request_for_client_async(uri.clone(), "par-client".into(), "wrong".into())
            .await
            .is_err());
        anyhow::ensure!(store
            .clone()
            .resume_request_for_client_async(
                uri.clone(),
                "wrong-client".into(),
                continuation.clone()
            )
            .await
            .is_err());
        let resumed = store
            .resume_request_for_client_async(uri.clone(), "par-client".into(), continuation)
            .await
            .map_err(|error| anyhow::anyhow!(error.error))?;
        anyhow::ensure!(resumed.response_mode.as_deref() == Some("form_post"));
        for _ in 0..32 {
            let backend = backend.clone();
            let uri = uri.clone();
            jobs.spawn(async move {
                backend
                    .consume(&uri)
                    .await
                    .map(|row| row.map_or(Lookup::Missing, |value| Lookup::Found(Box::new(value))))
            });
        }
        let mut winners = 0;
        while let Some(result) = jobs.join_next().await {
            if matches!(result??, Lookup::Found(_)) {
                winners += 1;
            }
        }
        anyhow::ensure!(winners == 1 && backend.load(&uri).await?.is_none());
        Ok(())
    }
    .await;
    fixture.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; corrupt stored binding, expiry cleanup and store failure"]
async fn pg_par_invalid_payload_and_unavailable_store_fail_closed() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result=async {
        let backend=PostgresParRequestStore::new(grant_database(fixture.pool.clone()));
        let uri=crate::par::ParStore::generate_request_uri();backend.insert(&uri,stored()?).await?;
        sqlx::query("UPDATE aegaeon.runtime_par_requests SET client_digest=$1").bind(vec![0u8;32]).execute(&fixture.pool).await?;
        anyhow::ensure!(backend.load(&uri).await.is_err());
        backend.remove(&uri).await?;backend.insert(&uri,stored()?).await?;
        let mut tx=fixture.pool.begin().await?;
        sqlx::query("DELETE FROM aegaeon.runtime_par_requests").execute(&mut *tx).await?;tx.rollback().await?;
        anyhow::ensure!(backend.load(&uri).await?.is_some());
        sqlx::query("UPDATE aegaeon.runtime_par_requests SET expires_at=clock_timestamp()-interval '1 second'").execute(&fixture.pool).await?;
        anyhow::ensure!(backend.load(&uri).await?.is_none());
        anyhow::ensure!(matches!(backend.reserve(&uri,"par-client",&"a".repeat(43)).await?,Lookup::Missing));
        backend.cleanup().await?;
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_par_requests").fetch_one(&fixture.pool).await?;anyhow::ensure!(count==0);
        sqlx::query("DROP TABLE aegaeon.runtime_par_requests CASCADE").execute(&fixture.pool).await?;
        anyhow::ensure!(backend.load(&uri).await.is_err());anyhow::ensure!(backend.insert(&uri,stored()?).await.is_err());
        anyhow::ensure!(backend.consume(&uri).await.is_err());anyhow::ensure!(backend.reserve(&uri,"par-client",&"a".repeat(43)).await.is_err());
        Ok(())
    }.await;
    fixture.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; reservation rollback, invalid arguments and expiry after row lock"]
async fn pg_par_reservation_rollback_and_lock_expiry() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let backend = Arc::new(PostgresParRequestStore::new(grant_database(fixture.pool.clone())));
        let uri = crate::par::ParStore::generate_request_uri();
        let digest = sha256_digest(uri.as_bytes());
        let client = sha256_digest(b"par-client");
        let continuation = "a".repeat(43);
        backend.insert(&uri, stored()?).await?;
        for (client, continuation) in [(None, Some(continuation.as_str())), (Some(client.as_slice()), Some("short")), (Some(client.as_slice()), None)] {
            anyhow::ensure!(sqlx::query("SELECT * FROM aegaeon.reserve_runtime_par($1,$2,$3,$4)")
                .bind(backend.database.namespace.as_ref()).bind(digest.as_slice()).bind(client).bind(continuation)
                .execute(&fixture.pool).await.is_err());
        }
        let mut tx = fixture.pool.begin().await?;
        let outcome: i32 = sqlx::query_scalar("SELECT outcome FROM aegaeon.reserve_runtime_par($1,$2,$3,$4)")
            .bind(backend.database.namespace.as_ref()).bind(digest.as_slice()).bind(client.as_slice()).bind(&continuation)
            .fetch_one(&mut *tx).await?;
        anyhow::ensure!(outcome == 0);
        tx.rollback().await?;
        anyhow::ensure!(backend.load(&uri).await?.is_some_and(|row| row.authorize_continuation.is_none()));
        anyhow::ensure!(matches!(backend.reserve(&uri, "par-client", &continuation).await?, Lookup::Found(_)));
        backend.remove(&uri).await?;
        backend.insert(&uri, stored()?).await?;
        let mut tx = fixture.pool.begin().await?;
        sqlx::query("UPDATE aegaeon.runtime_par_requests SET expires_at=clock_timestamp()+interval '250 milliseconds'")
            .execute(&mut *tx).await?;
        let waiting_backend = backend.clone();
        let waiting_uri = uri.clone();
        let worker = tokio::spawn(async move { waiting_backend.reserve(&waiting_uri, "par-client", &continuation).await });
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=$1 AND wait_event_type='Lock' AND query LIKE 'SELECT outcome,payload,expiry FROM aegaeon.reserve_runtime_par%')")
                    .bind(&fixture.database).fetch_one(&fixture.admin).await?;
                if waiting { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<_, sqlx::Error>(())
        }).await??;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let expired: bool = sqlx::query_scalar("SELECT expires_at<=clock_timestamp() FROM aegaeon.runtime_par_requests")
                    .fetch_one(&mut *tx).await?;
                if expired { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<_, sqlx::Error>(())
        }).await??;
        tx.commit().await?;
        anyhow::ensure!(matches!(worker.await??, Lookup::Missing));
        let unreserved: bool = sqlx::query_scalar("SELECT continuation IS NULL FROM aegaeon.runtime_par_requests")
            .fetch_one(&fixture.pool).await?;
        anyhow::ensure!(unreserved);
        Ok(())
    }.await;
    fixture.finish().await?;
    result
}

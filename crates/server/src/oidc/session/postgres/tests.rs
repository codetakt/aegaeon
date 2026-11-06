use super::*;
use sqlx::{postgres::PgPoolOptions, Executor, PgPool};
use std::sync::Arc;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; oversized logout rolls back every event"]
async fn pg_oidc_logout_result_bounds_rollback_all_events() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result=async {
        fixture.pool.execute("INSERT INTO aegaeon.runtime_oidc_sessions(namespace,sid,user_id,auth_digest) SELECT 'bounded',gen_random_uuid(),'subject',sha256(i::text::bytea) FROM generate_series(1,129) i").await?;
        assert!(sqlx::query("SELECT * FROM aegaeon.logout_runtime_oidc_user('bounded','subject',60)").execute(&fixture.pool).await.is_err());
        let closed:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_oidc_sessions WHERE logout_jti IS NOT NULL").fetch_one(&fixture.pool).await?;
        assert_eq!(closed,0);
        let sid:Uuid=sqlx::query_scalar("SELECT sid FROM aegaeon.runtime_oidc_sessions LIMIT 1").fetch_one(&fixture.pool).await?;
        sqlx::query("INSERT INTO aegaeon.runtime_oidc_clients(namespace,sid,client_id) SELECT 'bounded',$1,i::text FROM generate_series(1,1025) i").bind(sid).execute(&fixture.pool).await?;
        assert!(sqlx::query("SELECT * FROM aegaeon.logout_runtime_oidc_session('bounded',$1,gen_random_uuid(),60)").bind(sid).execute(&fixture.pool).await.is_err());
        let closed:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_oidc_sessions WHERE logout_jti IS NOT NULL").fetch_one(&fixture.pool).await?;
        assert_eq!(closed,0);
        sqlx::query("DELETE FROM aegaeon.runtime_oidc_clients WHERE client_id='1025'").execute(&fixture.pool).await?;
        let row:(Uuid,String,Uuid,Vec<String>)=sqlx::query_as("SELECT * FROM aegaeon.logout_runtime_oidc_session('bounded',$1,gen_random_uuid(),60)").bind(sid).fetch_one(&fixture.pool).await?;
        assert_eq!(row.3.len(),1024);
        Ok::<_,anyhow::Error>(())
    }.await;
    fixture.finish().await?;
    result
}

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
        let name = format!("oidc_state_{}", Uuid::new_v4().simple());
        admin
            .execute(format!("CREATE DATABASE {name}").as_str())
            .await?;
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(admin.connect_options().as_ref().clone().database(&name))
            .await?;
        pool.execute("CREATE SCHEMA aegaeon").await?;
        sqlx::raw_sql(crate::organization_schema::component!(
            "runtime_oidc_sessions"
        ))
        .execute(&pool)
        .await?;
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
    fn backend(&self) -> PostgresOidcSessionBackend {
        PostgresOidcSessionBackend::new(self.database.clone())
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

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; shared OIDC binding, exact prepared sid and logout event idempotency"]
async fn pg_oidc_binding_and_logout_concurrency() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let backend = Arc::new(fixture.backend());
        let context = OidcSessionContext {
            user_id: "subject",
            auth_session_id: "browser-sid",
        };
        let first = backend
            .prepare(context, "client-a")
            .await
            .map_err(anyhow::Error::msg)?;
        let second = backend
            .prepare(context, "client-b")
            .await
            .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(first.sid() != second.sid());
        let mut connection = fixture.pool.acquire().await?;
        let first_commit = first
            .postgres_commit()
            .ok_or_else(|| anyhow::anyhow!("PG context missing"))?;
        first_commit
            .bind_on(&mut connection, true)
            .await
            .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(second
            .postgres_commit()
            .ok_or_else(|| anyhow::anyhow!("PG context missing"))?
            .bind_on(&mut connection, true)
            .await
            .is_err());
        drop(connection);
        let mut jobs = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let backend = backend.clone();
            jobs.spawn(async move { backend.get_or_create(context).await });
        }
        while let Some(result) = jobs.join_next().await {
            anyhow::ensure!(result?.map_err(anyhow::Error::msg)? == first.sid());
        }
        anyhow::ensure!(backend
            .add_client(first.sid(), "client-b")
            .await
            .map_err(anyhow::Error::msg)?);
        anyhow::ensure!(backend
            .get_or_create(OidcSessionContext {
                user_id: "wrong-subject",
                ..context
            })
            .await
            .is_err());
        for _ in 0..32 {
            let backend = backend.clone();
            let sid = first.sid().to_owned();
            jobs.spawn(async move {
                backend.logout_sid(&sid, 60).await.and_then(|event| {
                    event
                        .map(|event| event.jti)
                        .ok_or_else(|| "logout event missing".to_owned())
                })
            });
        }
        let mut jtis = std::collections::HashSet::new();
        while let Some(result) = jobs.join_next().await {
            jtis.insert(result?.map_err(anyhow::Error::msg)?);
        }
        anyhow::ensure!(jtis.len() == 1 && !jtis.contains(""));
        anyhow::ensure!(!backend
            .add_client(first.sid(), "late-client")
            .await
            .map_err(anyhow::Error::msg)?);
        let event = backend
            .logout_sid(first.sid(), 60)
            .await
            .map_err(anyhow::Error::msg)?
            .ok_or_else(|| anyhow::anyhow!("event missing"))?;
        anyhow::ensure!(event.client_ids == ["client-a", "client-b"]);
        let new_sid = backend
            .get_or_create(context)
            .await
            .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(new_sid != first.sid());
        anyhow::ensure!(backend
            .logout_auth_session(context.auth_session_id, 60)
            .await
            .map_err(anyhow::Error::msg)?
            .is_some_and(|event| event.sid == new_sid));
        Ok(())
    }
    .await;
    fixture.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; prepared OIDC transaction rollback, bounded dependent cleanup and DB failure"]
async fn pg_oidc_rollback_cleanup_and_unavailable_store() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result=async {
        let backend=fixture.backend();
        let context=OidcSessionContext {user_id:"subject",auth_session_id:"browser-sid"};
        let prepared=backend.prepare(context,"client").await.map_err(anyhow::Error::msg)?;
        let mut tx=fixture.pool.begin().await?;
        prepared.postgres_commit().ok_or_else(||anyhow::anyhow!("PG context missing"))?.bind_on(&mut tx,true).await.map_err(anyhow::Error::msg)?;
        tx.rollback().await?;
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_oidc_sessions").fetch_one(&fixture.pool).await?;anyhow::ensure!(count==0);
        let sid=backend.get_or_create(context).await.map_err(anyhow::Error::msg)?;
        backend.add_client(&sid,"client").await.map_err(anyhow::Error::msg)?;
        anyhow::ensure!(backend.logout_user("wrong-subject",60).await.map_err(anyhow::Error::msg)?.is_empty());
        anyhow::ensure!(backend.logout_user("subject",60).await.map_err(anyhow::Error::msg)?.len()==1);
        let live=backend.get_or_create(OidcSessionContext {auth_session_id:"live-browser",..context}).await.map_err(anyhow::Error::msg)?;
        sqlx::query("UPDATE aegaeon.runtime_oidc_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE logout_jti IS NOT NULL").execute(&fixture.pool).await?;
        anyhow::ensure!(backend.logout_sid(&sid,60).await.map_err(anyhow::Error::msg)?.is_none());
        backend.cleanup().await.map_err(anyhow::Error::msg)?;
        let counts:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM aegaeon.runtime_oidc_sessions),(SELECT count(*) FROM aegaeon.runtime_oidc_auth_bindings),(SELECT count(*) FROM aegaeon.runtime_oidc_clients)").fetch_one(&fixture.pool).await?;
        anyhow::ensure!(counts==(1,1,0));
        anyhow::ensure!(backend.get_or_create(OidcSessionContext{auth_session_id:"live-browser",..context}).await.map_err(anyhow::Error::msg)?==live);
        sqlx::query("DROP TABLE aegaeon.runtime_oidc_sessions CASCADE").execute(&fixture.pool).await?;
        anyhow::ensure!(backend.get_or_create(context).await.is_err());anyhow::ensure!(backend.logout_sid(&sid,60).await.is_err());
        Ok(())
    }.await;
    fixture.finish().await?;
    result
}

#[path = "tests/cleanup.rs"]
mod cleanup_tests;
#[path = "tests/delivery.rs"]
mod delivery_tests;

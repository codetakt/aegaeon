use super::*;
use sqlx::{postgres::PgPoolOptions, Executor};
use std::sync::Arc;
mod availability;
fn migration() -> &'static str {
    crate::organization_schema::component!("runtime_management_sessions")
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
        let database = format!("management_session_{}", Uuid::new_v4().simple());
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
#[ignore = "requires isolated PostgreSQL; shared capacity, session lookup, deletion and expiry"]
async fn pg_management_sessions_capacity_and_readonly_lookup() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result=async {
        let backend=Arc::new(PostgresManagementSessions::new(fixture.pool.clone(),"management-tests".into()));
        let administrator=Uuid::new_v4();let now=crate::util::now_unix_epoch_secs()?;
        anyhow::ensure!(backend.create(administrator,u64::MAX,60,4).await.map_err(anyhow::Error::msg)?.is_none());
        let first=backend.create(administrator,now-1,60,4).await.map_err(anyhow::Error::msg)?.ok_or_else(||anyhow::anyhow!("session missing"))?;
        let reopened=PostgresManagementSessions::new(fixture.pool.clone(),"management-tests".into());
        let read=reopened.get(&first,now,60).await.map_err(anyhow::Error::msg)?.ok_or_else(||anyhow::anyhow!("session missing"))?;
        anyhow::ensure!(read.administrator_id==administrator && read.created_at_epoch_secs==now-1 && read.is_human_session());
        anyhow::ensure!(reopened.get(&first,now-2,60).await.map_err(anyhow::Error::msg)?.is_none());
        anyhow::ensure!(reopened.get(&first,now,1).await.map_err(anyhow::Error::msg)?.is_none());
        let foreign=PostgresManagementSessions::new(fixture.pool.clone(),"foreign-management".into());
        anyhow::ensure!(foreign.get(&first,now,60).await.map_err(anyhow::Error::msg)?.is_none());
        anyhow::ensure!(!foreign.delete(&first).await.map_err(anyhow::Error::msg)?);
        let mut locked=fixture.pool.begin().await?;
        sqlx::query("SELECT 1 FROM aegaeon.runtime_management_session_scopes FOR UPDATE").execute(&mut *locked).await?;
        anyhow::ensure!(tokio::time::timeout(Duration::from_secs(1),reopened.get(&first,now,60)).await?.map_err(anyhow::Error::msg)?.is_some());
        locked.rollback().await?;
        let mut jobs=tokio::task::JoinSet::new();
        for _ in 0..32 { let backend=backend.clone();jobs.spawn(async move { backend.create(administrator,now,60,4).await }); }
        let mut sessions=Vec::new();
        while let Some(result)=jobs.join_next().await { sessions.push(result?.map_err(anyhow::Error::msg)?.ok_or_else(||anyhow::anyhow!("concurrent session missing"))?); }
        anyhow::ensure!(sessions.len()==32);
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_management_sessions").fetch_one(&fixture.pool).await?;anyhow::ensure!(count==4);
        anyhow::ensure!(backend.get(&first,now,60).await.map_err(anyhow::Error::msg)?.is_none());
        let mut live=Vec::new();
        for sid in sessions { if backend.get(&sid,now,60).await.map_err(anyhow::Error::msg)?.is_some() { live.push(sid); } }
        anyhow::ensure!(live.len()==4);
        for sid in live { anyhow::ensure!(backend.delete(&sid).await.map_err(anyhow::Error::msg)?);anyhow::ensure!(!reopened.delete(&sid).await.map_err(anyhow::Error::msg)?); }
        let expired=backend.create(administrator,now,60,4).await.map_err(anyhow::Error::msg)?.ok_or_else(||anyhow::anyhow!("session missing"))?;
        sqlx::query("UPDATE aegaeon.runtime_management_sessions SET expires_at=clock_timestamp()-interval '1 second'").execute(&fixture.pool).await?;
        anyhow::ensure!(backend.get(&expired,now,60).await.map_err(anyhow::Error::msg)?.is_none());
        backend.cleanup().await.map_err(anyhow::Error::msg)?;
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_management_sessions").fetch_one(&fixture.pool).await?;anyhow::ensure!(count==0);
        sqlx::query("DROP TABLE aegaeon.runtime_management_sessions").execute(&fixture.pool).await?;
        anyhow::ensure!(backend.create(administrator,now,60,4).await.is_err());
        anyhow::ensure!(backend.get(&expired,now,60).await.is_err());
        anyhow::ensure!(backend.delete(&expired).await.is_err());
        Ok(())
    }.await;
    fixture.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; collisions and rollback preserve existing capacity"]
async fn pg_management_sessions_collision_and_rollback() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result=async {
        let backend=PostgresManagementSessions::new(fixture.pool.clone(),"management-tests".into());
        let administrator=Uuid::new_v4();let now=crate::util::now_unix_epoch_secs()?;
        let sid=backend.create(administrator,now,60,1).await.map_err(anyhow::Error::msg)?.ok_or_else(||anyhow::anyhow!("session missing"))?;
        let digest=aegaeon_crypto::hash::sha256_digest(sid.as_bytes());
        let collision=sqlx::query("SELECT aegaeon.create_runtime_management_session('management-tests',$1,$2,$3,clock_timestamp()+interval '1 minute',1)")
            .bind(digest.as_slice()).bind(Uuid::new_v4()).bind(i64::try_from(now)?).execute(&fixture.pool).await;
        anyhow::ensure!(collision.is_err());
        anyhow::ensure!(backend.get(&sid,now,60).await.map_err(anyhow::Error::msg)?.is_some_and(|s|s.administrator_id==administrator));
        let replacement=aegaeon_crypto::hash::sha256_digest(b"different-session");
        let mut tx=fixture.pool.begin().await?;
        sqlx::query("SELECT aegaeon.create_runtime_management_session('management-tests',$1,$2,$3,clock_timestamp()+interval '1 minute',1)")
            .bind(replacement.as_slice()).bind(Uuid::new_v4()).bind(i64::try_from(now)?).execute(&mut *tx).await?;
        tx.rollback().await?;
        anyhow::ensure!(backend.get(&sid,now,60).await.map_err(anyhow::Error::msg)?.is_some_and(|s|s.administrator_id==administrator));
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_management_sessions").fetch_one(&fixture.pool).await?;anyhow::ensure!(count==1);
        for capacity in [0,1_000_001] {
            let invalid=sqlx::query("SELECT aegaeon.create_runtime_management_session('management-tests',$1,$2,$3,clock_timestamp()+interval '1 minute',$4)")
                .bind(replacement.as_slice()).bind(Uuid::new_v4()).bind(i64::try_from(now)?).bind(capacity).execute(&fixture.pool).await;
            anyhow::ensure!(invalid.is_err());
        }
        Ok(())
    }.await;
    fixture.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; one-connection final check and concurrent logout"]
async fn pg_management_session_final_check_reuses_transaction_and_holds_revocation(
) -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let single = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(1))
            .connect_with(fixture.pool.connect_options().as_ref().clone())
            .await?;
        let backend = PostgresManagementSessions::new(single.clone(), "management-tests".into());
        let now = crate::util::now_unix_epoch_secs()?;
        let sid = backend
            .create(Uuid::new_v4(), now, 60, 4)
            .await
            .map_err(anyhow::Error::msg)?
            .ok_or_else(|| anyhow::anyhow!("session missing"))?;
        let mut tx = single.begin().await?;
        anyhow::ensure!(tokio::time::timeout(
            Duration::from_secs(1),
            backend.get_in_transaction(&mut tx, &sid, now, 60)
        )
        .await?
        .map_err(anyhow::Error::msg)?
        .is_some());
        let other =
            PostgresManagementSessions::new(fixture.pool.clone(), "management-tests".into());
        let copied = sid.clone();
        let mut logout = tokio::spawn(async move { other.delete(&copied).await });
        anyhow::ensure!(
            tokio::time::timeout(Duration::from_millis(100), &mut logout)
                .await
                .is_err()
        );
        tx.commit().await?;
        anyhow::ensure!(logout.await?.map_err(anyhow::Error::msg)?);
        anyhow::ensure!(backend
            .get(&sid, now, 60)
            .await
            .map_err(anyhow::Error::msg)?
            .is_none());
        single.close().await;
        Ok(())
    }
    .await;
    fixture.finish().await?;
    result
}

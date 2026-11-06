use super::*;
use sqlx::{postgres::PgPoolOptions, Executor};
use std::time::Duration;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; terminate an actual blocked team-authority read"]
async fn pg_management_team_visibility_connection_loss_is_503_and_recovers() -> anyhow::Result<()> {
    let admin = PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?)
        .await?;
    let database = format!("team_availability_{}", Uuid::new_v4().simple());
    admin
        .execute(format!("CREATE DATABASE {database}").as_str())
        .await?;
    let label = format!("team-availability-{}", Uuid::new_v4());
    let options = admin.connect_options().as_ref().clone().database(&database);
    let setup = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options.clone())
        .await?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(3))
        .connect_with(options.application_name(&label))
        .await?;
    let result = async {
        setup.execute("CREATE SCHEMA aegaeon; CREATE TABLE aegaeon.teams(id uuid PRIMARY KEY,status text); CREATE TABLE aegaeon.administrators(id uuid PRIMARY KEY,status text,kind text); CREATE TABLE aegaeon.team_memberships(team_id uuid,administrator_id uuid,role text)").await?;
        let team = Uuid::new_v4(); let administrator = Uuid::new_v4();
        sqlx::query("INSERT INTO aegaeon.teams VALUES($1,'ACTIVE')").bind(team).execute(&setup).await?;
        sqlx::query("INSERT INTO aegaeon.administrators VALUES($1,'ACTIVE','HUMAN')").bind(administrator).execute(&setup).await?;
        sqlx::query("INSERT INTO aegaeon.team_memberships VALUES($1,$2,'OWNER')").bind(team).bind(administrator).execute(&setup).await?;
        let mut lock = setup.begin().await?;
        sqlx::query("LOCK TABLE aegaeon.team_memberships IN ACCESS EXCLUSIVE MODE").execute(&mut *lock).await?;
        let query_pool = pool.clone();
        let session = ManagementSession::human(administrator, 1);
        let query = tokio::spawn(async move {
            ensure_team_visible_as(&query_pool, team, &session, "crash-request", management_team_not_found).await
        });
        let terminated = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let pid: Option<i32> = sqlx::query_scalar("SELECT pid FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE '%aegaeon.team_memberships%'")
                    .bind(&label).fetch_optional(&admin).await?;
                if let Some(pid) = pid {
                    let killed: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)").bind(pid).fetch_one(&admin).await?;
                    anyhow::ensure!(killed); return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await;
        lock.rollback().await?;
        terminated??;
        let response = tokio::time::timeout(Duration::from_secs(3), query).await??
            .expect_err("terminated authority read must refuse");
        anyhow::ensure!(response.status() == StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), 4096).await?;
        let body: serde_json::Value = serde_json::from_slice(&body)?;
        anyhow::ensure!(body["errorCode"] == "temporarily_unavailable" && body["requestId"] == "crash-request");
        let session = ManagementSession::human(administrator, 1);
        anyhow::ensure!(ensure_team_visible_as(&pool, team, &session, "recovered-request", management_team_not_found).await.is_ok());
        // Schema/privilege errors must not be described as transient outages.
        for code in ["42501", "42601"] {
            let error = setup.execute(format!("DO $$ BEGIN RAISE SQLSTATE '{code}' USING MESSAGE='fixture'; END $$").as_str()).await.unwrap_err();
            anyhow::ensure!(database_failure(&error, "permanent", "fixture").status() == StatusCode::INTERNAL_SERVER_ERROR);
        }
        Ok(())
    }.await;
    crate::organizations::lifecycle::close_pool(&pool).await;
    crate::organizations::lifecycle::close_pool(&setup).await;
    admin
        .execute(format!("DROP DATABASE {database}").as_str())
        .await?;
    crate::organizations::lifecycle::close_pool(&admin).await;
    result
}

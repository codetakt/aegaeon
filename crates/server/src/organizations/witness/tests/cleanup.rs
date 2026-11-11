//! Actual held backends distinguish cleanup refusal from successful removal.
use super::*;
use tokio::time::timeout;

mod autovacuum;

struct Recovery {
    observer: PgConnection,
    database: String,
    runtime: String,
    maintenance: String,
}

impl Recovery {
    async fn new(fixture: &Fixture) -> anyhow::Result<Self> {
        Ok(Self {
            observer: PgConnection::connect(&std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?)
                .await?,
            database: fixture.database.clone(),
            runtime: fixture.runtime.clone(),
            maintenance: fixture.maintenance.clone(),
        })
    }

    async fn database_exists(&mut self) -> anyhow::Result<bool> {
        Ok(
            sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1)")
                .bind(&self.database)
                .fetch_one(&mut self.observer)
                .await?,
        )
    }

    async fn recover(mut self, held: Option<PgConnection>) -> TestResult {
        let result = timeout(Duration::from_secs(3), async {
            if let Some(held) = held {
                held.close().await?;
            }
            loop {
                let remaining: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE datname=$1 AND backend_type IS DISTINCT FROM 'autovacuum worker'",
                )
                .bind(&self.database)
                .fetch_one(&mut self.observer)
                .await?;
                if remaining == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            if self.database_exists().await? {
                self.observer
                    .execute(format!("DROP DATABASE {}", self.database).as_str())
                    .await?;
                sqlx::raw_sql(&format!("DROP ROLE {},{},aegaeon_organization_witness_runtime,aegaeon_organization_witness_maintenance,aegaeon_organization_witness_owner", self.runtime, self.maintenance))
                    .execute(&mut self.observer).await?;
            }
            anyhow::ensure!(!self.database_exists().await?);
            Ok::<_, anyhow::Error>(())
        })
        .await
        .map_err(anyhow::Error::from)
        .and_then(|result| result);
        let close = timeout(Duration::from_secs(3), self.observer.close())
            .await
            .map_err(anyhow::Error::from)
            .and_then(|result| result.map_err(Into::into));
        result.and(close)
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL; observes a held backend before ordinary witness cleanup"]
async fn pg_witness_fixture_cleanup_waits_for_owned_backend() -> TestResult {
    let fixture = Fixture::new().await?;
    let mut recovery = Recovery::new(&fixture).await?;
    let mut held = Some(PgConnection::connect_with(&fixture.options).await?);
    let mut finishing = Box::pin(fixture.finish());
    let result = async {
        anyhow::ensure!(timeout(Duration::from_millis(50), finishing.as_mut())
            .await
            .is_err());
        anyhow::ensure!(recovery.database_exists().await?);
        let value: i32 = sqlx::query_scalar("SELECT 1")
            .fetch_one(held.as_mut().unwrap())
            .await?;
        anyhow::ensure!(value == 1);
        held.take().unwrap().close().await?;
        finishing.as_mut().await?;
        anyhow::ensure!(!recovery.database_exists().await?);
        Ok(())
    }
    .await;
    drop(finishing);
    let cleanup = recovery.recover(held).await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL; a live backend must yield an error with its identity"]
async fn pg_witness_fixture_cleanup_returns_live_backend_error() -> TestResult {
    let fixture = Fixture::new().await?;
    let mut recovery = Recovery::new(&fixture).await?;
    let mut held = PgConnection::connect_with(&fixture.options).await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut held)
        .await?;
    let result = async {
        // A client-controlled label must never grant the server-maintenance
        // exemption used by ordinary DROP DATABASE.
        sqlx::query("SET application_name = 'autovacuum worker'")
            .execute(&mut held)
            .await?;
        let error = fixture
            .finish()
            .await
            .expect_err("held backend must refuse cleanup");
        let message = error.to_string();
        anyhow::ensure!(message.contains("all witness connections must actually finish"));
        anyhow::ensure!(message.contains("remaining=1"));
        anyhow::ensure!(message.contains(&pid.to_string()));
        anyhow::ensure!(message.contains("backend_start"));
        anyhow::ensure!(message.contains("backend_type"));
        anyhow::ensure!(message.contains("client backend"));
        anyhow::ensure!(recovery.database_exists().await?);
        let still_live: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut held)
            .await?;
        anyhow::ensure!(
            still_live == pid,
            "cleanup must not terminate the held backend"
        );
        Ok(())
    }
    .await;
    let cleanup = recovery.recover(Some(held)).await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL; identifies held control and deployment connection origins"]
async fn pg_witness_fixture_cleanup_reports_connection_call_sites() -> TestResult {
    let fixture = Fixture::new().await?;
    let mut recovery = Recovery::new(&fixture).await?;
    let control_line = line!() + 1;
    let control_future = fixture.connect(Role::Runtime);
    let deployment_line = line!() + 1;
    let deployment_future = deployment::connect(&fixture, Role::Runtime);
    // Poll elsewhere: the label must identify creation, not the await/helper.
    let control = control_future.await?;
    let deployment = deployment_future.await?;
    let result = async {
        let rows: Vec<(i32, String)> = sqlx::query_as(
            "SELECT pid,application_name FROM pg_stat_activity WHERE datname=$1 AND usename=$2 ORDER BY pid",
        )
        .bind(&fixture.database)
        .bind(&fixture.runtime)
        .fetch_all(&mut recovery.observer)
        .await?;
        anyhow::ensure!(rows.len() == 2);
        for (kind, line) in [("control", control_line), ("deployment", deployment_line)] {
            anyhow::ensure!(rows.iter().any(|(_, name)|
                name.starts_with(&format!("witness-test:{kind}:"))
                    && name.contains(&format!("cleanup.rs:{line}:"))));
        }
        let error = fixture.finish().await.err().ok_or_else(|| {
            anyhow::anyhow!("held control connections must refuse cleanup")
        })?;
        let message = error.to_string();
        anyhow::ensure!(message.contains("remaining=2"));
        for (pid, name) in rows {
            anyhow::ensure!(message.contains(&pid.to_string()) && message.contains(&name));
            anyhow::ensure!(name.len() <= 63);
        }
        anyhow::ensure!(recovery.database_exists().await?);
        Ok(())
    }
    .await;
    let control_close = control.close().await;
    let deployment_close = deployment.close().await;
    let cleanup = recovery.recover(None).await;
    result
        .and(control_close.map_err(Into::into))
        .and(deployment_close.map_err(Into::into))
        .and(cleanup)
}

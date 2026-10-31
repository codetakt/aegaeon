//! Actual independent-store finalization fault boundary; test-only authority.
use super::*;

impl CallerFixture {
    pub(crate) async fn creation_rows(
        &self,
        kind: &str,
    ) -> anyhow::Result<Vec<(Uuid, String, String, i32)>> {
        let mut connection = PgConnection::connect_with(&self.fixture.options).await?;
        let rows = sqlx::query_as("SELECT owner_id,subject,state,attempt FROM organization_witness.creations WHERE environment_id=$1 AND kind=$2 ORDER BY subject COLLATE \"C\"")
            .bind(self.scope.environment_id).bind(kind).fetch_all(&mut connection).await;
        let close = connection.close().await;
        let rows = rows?;
        close?;
        Ok(rows)
    }

    pub(crate) async fn run_new_environment<T>(
        &self,
        environment_id: Uuid,
        future: impl std::future::Future<Output = T>,
    ) -> anyhow::Result<T> {
        // A second Environment shares the installed control supplier. Its fixed
        // cluster roles must not be installed twice by overlapping fixtures.
        let scope = Scope {
            environment_id,
            deployment_id: Uuid::new_v4(),
        };
        let plan = super::super::history::plan(scope, &[])?;
        let mut maintenance = self.fixture.connect(Role::Maintenance).await?;
        let operation = super::super::history::enrolled(&mut maintenance, scope, &plan).await?;
        let selected =
            super::super::history::activated(&mut maintenance, scope, operation, &plan).await?;
        maintenance.close().await?;
        let work = Work::begin(
            self.fixture.connect(Role::Runtime).await?,
            request_work::Admission::isolated_for_test()?,
            scope,
            &selected,
        )
        .await?;
        let result = work.store_scope(future).await;
        let completed = work.complete().await;
        let value = result?;
        anyhow::ensure!(completed?.pending == 0);
        Ok(value)
    }

    pub(crate) async fn creation_finish_barrier(&self) -> anyhow::Result<PgConnection> {
        let mut connection = PgConnection::connect_with(&self.fixture.options).await?;
        sqlx::raw_sql("BEGIN; LOCK TABLE organization_witness.creation_counts IN SHARE MODE")
            .execute(&mut connection)
            .await?;
        Ok(connection)
    }

    pub(crate) async fn disconnect_creation_finish(&self) -> anyhow::Result<()> {
        let mut connection = PgConnection::connect_with(&self.fixture.options).await?;
        let observed = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let pid: Option<i32> = sqlx::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename=$1 AND wait_event_type='Lock' AND query LIKE '%organization_witness.creation_finish%'")
                    .bind(&self.fixture.runtime).fetch_optional(&mut connection).await?;
                if let Some(pid) = pid { return Ok::<_, sqlx::Error>(pid); }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await;
        let result = match observed {
            Ok(Ok(pid)) => sqlx::query_scalar::<_, bool>("SELECT pg_terminate_backend($1)")
                .bind(pid)
                .fetch_one(&mut connection)
                .await
                .map_err(anyhow::Error::from),
            Ok(Err(error)) => Err(error.into()),
            Err(error) => Err(error.into()),
        };
        let close = connection.close().await;
        anyhow::ensure!(result?, "owned finalization backend was not terminated");
        close?;
        Ok(())
    }
}

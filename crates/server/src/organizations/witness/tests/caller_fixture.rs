//! A real isolated control supplier for consecutive caller operations. Test only.
use super::*;
use crate::organizations::request_work;
use crate::organizations::witness::work::Work;

mod creation;
mod http;
mod observed;
mod work;
pub(super) use work::CallerWork;

pub(crate) struct CallerFixture {
    fixture: Fixture,
    scope: Scope,
    selected: Selection,
    observed: observed::Stores,
}

impl CallerFixture {
    pub(crate) async fn retained_creation(
        &mut self,
        subject: &str,
    ) -> anyhow::Result<(Uuid, String, i32)> {
        Ok(sqlx::query_as("SELECT owner_id,state,attempt FROM organization_witness.creations WHERE environment_id=$1 AND subject=$2")
            .bind(self.scope.environment_id).bind(subject).fetch_one(&mut self.fixture.owner).await?)
    }

    pub(crate) async fn wait_for_creation_prepare(&self) -> anyhow::Result<()> {
        let mut connection = PgConnection::connect_with(&self.fixture.options).await?;
        let result = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND wait_event_type='Lock' AND query LIKE '%organization_witness.creation_prepare%')")
                    .bind(&self.fixture.runtime).fetch_one(&mut connection).await?;
                if waiting { return Ok::<_, sqlx::Error>(()); }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await;
        let close = connection.close().await;
        result??;
        close?;
        Ok(())
    }
    pub(crate) async fn history_append_barrier(&self) -> anyhow::Result<PgConnection> {
        let mut connection = PgConnection::connect_with(&self.fixture.options).await?;
        sqlx::raw_sql("BEGIN; LOCK TABLE organization_witness.history_entries IN SHARE MODE")
            .execute(&mut connection)
            .await?;
        Ok(connection)
    }

    pub(crate) async fn wait_for_history_append(&self) -> anyhow::Result<()> {
        let mut connection = PgConnection::connect_with(&self.fixture.options).await?;
        let result = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND wait_event_type='Lock' AND query LIKE '%organization_witness.history_reserve%')")
                    .bind(&self.fixture.runtime).fetch_one(&mut connection).await?;
                if waiting { return Ok::<_, sqlx::Error>(()); }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await;
        let close = connection.close().await;
        result??;
        close?;
        Ok(())
    }

    pub(crate) async fn retained_subjects(&mut self, owner: Uuid) -> anyhow::Result<Vec<String>> {
        Ok(sqlx::query_scalar("SELECT subject FROM organization_witness.history_entries WHERE environment_id=$1 AND owner_id=$2 AND kind=1 ORDER BY subject COLLATE \"C\"")
            .bind(self.scope.environment_id).bind(owner).fetch_all(&mut self.fixture.owner).await?)
    }

    pub(crate) async fn begin(&self) -> anyhow::Result<CallerWork> {
        self.begin_class(request_work::CapacityClass::Ordinary)
            .await
    }

    pub(crate) async fn begin_class(
        &self,
        class: request_work::CapacityClass,
    ) -> anyhow::Result<CallerWork> {
        let local = request_work::Admission::isolated_class_for_test(class)?;
        self.begin_observed(&self.observed, local)
            .await
            .map_err(Into::into)
    }

    pub(crate) async fn run<T>(
        &self,
        future: impl std::future::Future<Output = T>,
    ) -> anyhow::Result<T> {
        self.run_observed(&self.observed, future).await
    }

    pub(crate) async fn pending(&self) -> anyhow::Result<u32> {
        let mut runtime = self.fixture.connect(Role::Runtime).await?;
        let current = runtime.current(self.scope).await;
        let close = runtime.close().await;
        let state = current?;
        close?;
        Ok(state.pending)
    }

    pub(crate) async fn pending_work(&self) -> anyhow::Result<super::super::PendingWork> {
        let mut maintenance = self.fixture.connect(Role::Maintenance).await?;
        let observed = maintenance.pending(self.scope).await;
        let close = maintenance.close().await;
        close?;
        Ok(observed?)
    }

    pub(crate) async fn retire_epoch(&mut self) -> anyhow::Result<()> {
        let mut maintenance = self.fixture.connect(Role::Maintenance).await?;
        let current = maintenance.current(self.scope).await?;
        anyhow::ensure!(current.pending == 0);
        let operation = Uuid::new_v4();
        let fenced = maintenance
            .fence(self.scope, operation, current.revision)
            .await?;
        let mut next = self.selected.clone();
        next.epoch = Uuid::new_v4();
        let prepared = maintenance
            .prepare(self.scope, operation, fenced.revision, &next)
            .await?;
        {
            let stores = &self.observed;
            let (mut primary, mut token) = stores.connect().await?;
            maintenance
                .pin_store_progress(
                    self.scope,
                    operation,
                    prepared.revision,
                    &mut primary,
                    &mut token,
                )
                .await?;
            primary.close().await?;
            token.close();
            self.bind_observed_child(stores, next.epoch).await?;
        }
        maintenance
            .activate(
                self.scope,
                operation,
                prepared.revision,
                &next.acceptance_sha256,
            )
            .await?;
        maintenance.close().await?;
        self.selected = next;
        Ok(())
    }

    pub(crate) async fn finish(self) -> TestResult {
        self.fixture.finish().await
    }
}

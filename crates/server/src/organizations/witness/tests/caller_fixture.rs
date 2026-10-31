//! A real isolated control supplier for consecutive caller operations. Test only.
use super::*;
use crate::organizations::request_work;
use crate::organizations::witness::work::Work;

mod http;

pub(crate) struct CallerFixture {
    fixture: Fixture,
    scope: Scope,
    selected: Selection,
}

impl CallerFixture {
    pub(crate) async fn new(environment_id: Uuid) -> anyhow::Result<Self> {
        anyhow::ensure!(!environment_id.is_nil());
        let fixture = Fixture::new().await?;
        let scope = Scope {
            environment_id,
            deployment_id: Uuid::new_v4(),
        };
        let selected = selection();
        let mut maintenance = fixture.connect(Role::Maintenance).await?;
        let operation = Uuid::new_v4();
        maintenance.initialize(scope, operation).await?;
        maintenance.prepare(scope, operation, 1, &selected).await?;
        maintenance
            .activate(scope, operation, 2, &selected.acceptance_sha256)
            .await?;
        maintenance.close().await?;
        Ok(Self {
            fixture,
            scope,
            selected,
        })
    }

    pub(crate) async fn begin(&self) -> anyhow::Result<Work> {
        self.begin_class(request_work::CapacityClass::Ordinary)
            .await
    }

    pub(crate) async fn begin_class(
        &self,
        class: request_work::CapacityClass,
    ) -> anyhow::Result<Work> {
        Ok(Work::begin(
            self.fixture.connect(Role::Runtime).await?,
            request_work::Admission::isolated_class_for_test(class)?,
            self.scope,
            &self.selected,
        )
        .await?)
    }

    pub(crate) async fn run<T>(
        &self,
        future: impl std::future::Future<Output = T>,
    ) -> anyhow::Result<T> {
        let work = self.begin().await?;
        let result = work.store_scope(future).await;
        let completion = work.complete().await;
        let value = result?;
        completion?;
        Ok(value)
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

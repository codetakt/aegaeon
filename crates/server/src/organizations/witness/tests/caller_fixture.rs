//! A real isolated control supplier for consecutive caller operations. Test only.
use super::*;
use crate::organizations::request_work;
use crate::organizations::witness::work::Work;

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
        Ok(Work::begin(
            self.fixture.connect(Role::Runtime).await?,
            request_work::Admission::isolated_for_test()?,
            self.scope,
            &self.selected,
        )
        .await?)
    }

    pub(crate) async fn pending(&self) -> anyhow::Result<u32> {
        let mut runtime = self.fixture.connect(Role::Runtime).await?;
        let current = runtime.current(self.scope).await;
        let close = runtime.close().await;
        let state = current?;
        close?;
        Ok(state.pending)
    }

    pub(crate) async fn finish(self) -> TestResult {
        self.fixture.finish().await
    }
}

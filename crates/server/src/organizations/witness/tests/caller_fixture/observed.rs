//! Explicit data suppliers for protocol composition tests; not qualification.
use super::*;
use crate::organizations::store_observation::{Postgres, Redis};
use crate::organizations::witness::deployment::{work::Work as ParentWork, DeploymentId};

pub(super) struct Stores {
    primary: PgConnectOptions,
    token: redis::Client,
    pub(super) parent: Selection,
}
impl Stores {
    pub(super) async fn connect(&self) -> anyhow::Result<(Postgres, Redis)> {
        let primary = Postgres::observe(PgConnection::connect_with(&self.primary).await?).await?;
        let token = Redis::observe(self.token.get_multiplexed_async_connection().await?).await?;
        Ok((primary, token))
    }
}
impl CallerFixture {
    /// Test-only adapter: the primary is explicit and Redis must be supplied by
    /// the shared-store test driver. No default or in-memory fallback is allowed.
    pub(crate) async fn with_test_stores(
        environment_id: Uuid,
        primary: PgConnectOptions,
    ) -> anyhow::Result<Self> {
        Self::with_observed_stores(
            environment_id,
            primary,
            redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?,
        )
        .await
    }

    pub(crate) async fn with_observed_stores(
        environment_id: Uuid,
        primary: PgConnectOptions,
        token: redis::Client,
    ) -> anyhow::Result<Self> {
        Self::observed_scope(environment_id, primary, token, None).await
    }

    pub(crate) async fn with_observed_history(
        environment_id: Uuid,
        primary: PgConnectOptions,
        token: redis::Client,
        owners: &[(Uuid, Vec<&str>)],
    ) -> anyhow::Result<Self> {
        Self::observed_scope(environment_id, primary, token, Some(owners)).await
    }

    async fn observed_scope(
        environment_id: Uuid,
        primary: PgConnectOptions,
        token: redis::Client,
        owners: Option<&[(Uuid, Vec<&str>)]>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(!environment_id.is_nil());
        let fixture = Fixture::new().await?;
        let scope = Scope {
            environment_id,
            deployment_id: Uuid::new_v4(),
        };
        let plan = owners
            .map(|owners| super::super::history::plan(scope, owners))
            .transpose()?;
        let mut selected = selection();
        if let Some(plan) = &plan {
            selected.history_sha256 = plan.digest();
        }
        let stores = Stores {
            primary,
            token,
            parent: Selection {
                epoch: Uuid::new_v4(),
                ..selected.clone()
            },
        };
        super::super::store_supplier::application(
            &stores.primary,
            &stores.token,
            scope.deployment_id,
        )
        .await?;
        let (mut primary, mut token) = stores.connect().await?;
        let deployment = DeploymentId::new(scope.deployment_id)?;
        let mut maintenance =
            super::super::deployment::connect(&fixture, Role::Maintenance).await?;
        let parent_operation = Uuid::new_v4();
        maintenance.initialize(deployment, parent_operation).await?;
        maintenance
            .prepare(deployment, parent_operation, 1, &stores.parent)
            .await?;
        maintenance
            .pin_store_progress(deployment, parent_operation, 2, &mut primary, &mut token)
            .await?;
        maintenance
            .activate(
                deployment,
                parent_operation,
                2,
                &stores.parent.acceptance_sha256,
            )
            .await?;
        let environment = maintenance.environment_maintenance()?;
        let operation = if let Some(plan) = &plan {
            super::super::history::enrolled(environment, scope, plan).await?
        } else {
            let operation = Uuid::new_v4();
            environment.initialize(scope, operation).await?;
            operation
        };
        environment.prepare(scope, operation, 1, &selected).await?;
        environment
            .pin_store_progress(scope, operation, 2, &mut primary, &mut token)
            .await?;
        maintenance
            .bind_child(
                deployment,
                stores.parent.epoch,
                environment_id,
                selected.epoch,
            )
            .await?;
        maintenance
            .environment_maintenance()?
            .activate(scope, operation, 2, &selected.acceptance_sha256)
            .await?;
        primary.close().await?;
        token.close();
        maintenance.close().await?;
        Ok(Self {
            fixture,
            scope,
            selected,
            observed: stores,
        })
    }

    pub(super) async fn run_observed<T>(
        &self,
        stores: &Stores,
        future: impl std::future::Future<Output = T>,
    ) -> anyhow::Result<T> {
        let local = request_work::Admission::isolated_for_test()?;
        let work = self.begin_observed(stores, local).await?;
        let result = work.store_scope(future).await;
        work.complete().await?;
        Ok(result?)
    }

    pub(super) async fn begin_observed(
        &self,
        stores: &Stores,
        local: request_work::Admission,
    ) -> Result<CallerWork> {
        self.begin_observed_scope(stores, self.scope, &self.selected, local)
            .await
    }

    pub(super) async fn begin_observed_scope(
        &self,
        stores: &Stores,
        scope: Scope,
        selected: &Selection,
        local: request_work::Admission,
    ) -> Result<CallerWork> {
        let parent = ParentWork::begin(
            super::super::deployment::connect(&self.fixture, Role::Runtime).await?,
            local,
            DeploymentId::new(scope.deployment_id)?,
            &stores.parent,
            || async { stores.connect().await.map_err(|_| Error::Refused) },
        )
        .await?;
        let acquired = parent
            .child(
                super::super::deployment::connect(&self.fixture, Role::Runtime).await?,
                scope.environment_id,
                selected,
                || async { stores.connect().await.map_err(|_| Error::Refused) },
            )
            .await;
        match acquired {
            Ok(child) => Ok(CallerWork::observed(child, parent)),
            Err(error) => {
                // Confirmed refusal can drain; uncertain acquisition remains pending.
                let _ = parent.complete().await;
                Err(error)
            }
        }
    }

    pub(super) async fn bind_observed_child(&self, stores: &Stores, epoch: Uuid) -> Result<()> {
        let mut maintenance =
            super::super::deployment::connect(&self.fixture, Role::Maintenance).await?;
        maintenance
            .bind_child(
                DeploymentId::new(self.scope.deployment_id)?,
                stores.parent.epoch,
                self.scope.environment_id,
                epoch,
            )
            .await?;
        maintenance.close().await
    }

    pub(crate) async fn completed_parent_generation(&mut self) -> anyhow::Result<i64> {
        let mut runtime = super::super::deployment::connect(&self.fixture, Role::Runtime).await?;
        let state = runtime
            .current(DeploymentId::new(self.scope.deployment_id)?)
            .await;
        let close = runtime.close().await;
        anyhow::ensure!(state?.pending == 0, "deployment parent is still pending");
        close?;
        Ok(sqlx::query_scalar("SELECT COALESCE(max(generation),0) FROM organization_witness.deployment_store_observations WHERE deployment_id=$1 AND finished_wal IS NOT NULL")
            .bind(self.scope.deployment_id).fetch_one(&mut self.fixture.owner).await?)
    }

    pub(crate) async fn observed_generation(&mut self) -> anyhow::Result<i64> {
        Ok(sqlx::query_scalar("SELECT COALESCE(max(generation),0) FROM organization_witness.store_observations WHERE environment_id=$1 AND finished_wal IS NOT NULL")
            .bind(self.scope.environment_id).fetch_one(&mut self.fixture.owner).await?)
    }

    pub(crate) async fn completed_observations(&mut self) -> anyhow::Result<i64> {
        Ok(sqlx::query_scalar("SELECT count(*) FROM organization_witness.store_observations WHERE environment_id=$1 AND finished_wal IS NOT NULL")
            .bind(self.scope.environment_id).fetch_one(&mut self.fixture.owner).await?)
    }
}

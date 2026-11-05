//! Test-only local suppliers for the real parent/child execution boundary.
use super::*;
use crate::organizations::store_observation::{Postgres, Redis};
use crate::organizations::witness::work::{Execution, Starter};
use std::future::Future;

#[derive(Clone)]
pub(in crate::organizations::witness::tests) struct Start {
    options: PgConnectOptions,
    token: redis::Client,
    deployment: DeploymentId,
    parent: Selection,
    scope: Scope,
    child: Selection,
}

impl Start {
    pub(in crate::organizations::witness::tests) fn new(
        f: &Fixture,
        deployment: DeploymentId,
        parent: Selection,
        scope: Scope,
        child: Selection,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            options: f
                .options
                .clone()
                .username(&f.runtime)
                .password(&f.runtime_password),
            token: redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?,
            deployment,
            parent,
            scope,
            child,
        })
    }

    pub(in crate::organizations::witness::tests) async fn begin(
        &self,
        local: request_work::Admission,
    ) -> Result<super::super::caller_fixture::CallerWork> {
        self.begin_with_control(local, self.control().await?).await
    }

    /// Retain a known child connection for actual cancellation/failure tests.
    pub(in crate::organizations::witness::tests) async fn begin_with_control(
        &self,
        local: request_work::Admission,
        control: DeploymentControl,
    ) -> Result<super::super::caller_fixture::CallerWork> {
        let parent = Work::begin(
            self.control().await?,
            local,
            self.deployment,
            &self.parent,
            || self.stores("aegaeon-parent-progress-test"),
        )
        .await?;
        let acquired = parent
            .child(control, self.scope.environment_id, &self.child, || {
                self.stores("aegaeon-child-progress-test")
            })
            .await;
        let child = match acquired {
            Ok(child) => child,
            Err(error) => {
                let _ = parent.complete().await;
                return Err(error);
            }
        };
        Ok(super::super::caller_fixture::CallerWork::observed(
            child, parent,
        ))
    }

    pub(in crate::organizations::witness::tests) fn start_with_control<T, F>(
        self,
        local: request_work::Admission,
        control: DeploymentControl,
        operation: F,
    ) -> Execution<T>
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        let deadline = tokio::time::Instant::now() + local.execution_budget();
        Execution::from_worker(tokio::spawn(async move {
            tokio::time::timeout_at(deadline, async move {
                let work = self.begin_with_control(local, control).await?;
                let result = work.store_scope(operation).await?;
                work.complete().await?;
                Ok(result)
            })
            .await
            .map_err(|_| Error::Deadline)?
        }))
    }

    async fn control(&self) -> Result<DeploymentControl> {
        DeploymentControl::checked(
            PgConnection::connect_with(&self.options).await?,
            Role::Runtime,
        )
        .await
    }

    async fn stores(&self, application: &str) -> Result<(Postgres, Redis)> {
        let primary = Postgres::observe(
            PgConnection::connect_with(&self.options.clone().application_name(application)).await?,
        )
        .await
        .map_err(|_| Error::Refused)?;
        let token = Redis::observe(
            self.token
                .get_multiplexed_async_connection()
                .await
                .map_err(|_| Error::Refused)?,
        )
        .await
        .map_err(|_| Error::Refused)?;
        Ok((primary, token))
    }
}

impl Starter for Start {
    fn start<T, F>(
        self,
        local: request_work::Admission,
        operation: F,
        deadline: tokio::time::Instant,
    ) -> Execution<T>
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        Execution::from_worker(tokio::spawn(async move {
            tokio::time::timeout_at(deadline, async move {
                let work = self.begin(local).await?;
                let result = work.store_scope(operation).await?;
                work.complete().await?;
                Ok(result)
            })
            .await
            .map_err(|_| Error::Deadline)?
        }))
    }
}

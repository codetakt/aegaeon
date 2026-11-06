//! Retain deployment ownership through every child, driver and cleanup owner.
use super::*;
use crate::organizations::request_work::Admission as LocalAdmission;
use crate::organizations::store_observation::{Postgres, Redis};
use std::sync::Arc;

pub(in crate::organizations) struct Owner {
    durable: Admission,
    control: tokio::sync::Mutex<Option<DeploymentControl>>,
    observed: Arc<progress::DataObservations>,
    label: String,
}

impl Owner {
    pub(in crate::organizations::witness) fn matches_selection(
        &self,
        deployment: DeploymentId,
        selection: &Selection,
    ) -> bool {
        self.durable.deployment == deployment && self.durable.selection == *selection
    }
    pub(in crate::organizations) fn store_label(&self) -> &str {
        &self.label
    }
    pub(in crate::organizations) fn observations(
        &self,
    ) -> &super::super::store_progress::ObservedStores {
        &self.observed.stores
    }
    pub(in crate::organizations) fn matches_child(&self, child: &super::super::Admission) -> bool {
        child.scope.deployment_id == self.durable.deployment.0
            && child.binding.store_ids()
                == Some((
                    self.durable.selection.primary,
                    self.durable.selection.token_store,
                ))
    }
    async fn complete(&self) -> Result<State> {
        let mut control =
            tokio::time::timeout(std::time::Duration::from_secs(5), self.control.lock())
                .await
                .map_err(|_| Error::Deadline)?
                .take()
                .ok_or(Error::Refused)?;
        control.continuity_command("BEGIN").await?;
        let result = async {
            let previous = control.lock_completion_seal(&self.durable).await?;
            let next = Uuid::new_v4();
            self.observed
                .finish(&mut control, &self.durable, previous, next)
                .await?;
            control
                .advance_completion_seal(&self.durable, previous, next)
                .await?;
            control.complete(&self.durable).await
        }
        .await;
        let state = match result {
            Ok(state) => {
                control.continuity_command("COMMIT").await?;
                state
            }
            Err(error) => {
                let _ = control.continuity_command("ROLLBACK").await;
                return Err(error);
            }
        };
        control.close().await?;
        Ok(state)
    }
}

#[must_use]
pub struct Work {
    local: LocalAdmission,
    owner: Arc<Owner>,
    completed: bool,
}
struct Beginning {
    local: LocalAdmission,
    finished: bool,
}
impl Beginning {
    fn finish(&mut self) {
        // Borrow the entire Drop guard: capturing only its Copy flag in an
        // async move block leaves the original guard armed outside the future.
        self.finished = true;
    }
}
impl Drop for Beginning {
    fn drop(&mut self) {
        if !self.finished {
            self.local.close_until_restart();
        }
    }
}
impl Drop for Work {
    fn drop(&mut self) {
        if !self.completed {
            self.local.close_until_restart();
        }
    }
}

impl Work {
    /// Connection construction is invoked only after durable acquisition and
    /// observation begin. Cancellation retains pending history and closes capacity.
    pub async fn begin<F, Fut>(
        mut control: DeploymentControl,
        local: LocalAdmission,
        deployment: DeploymentId,
        selection: &Selection,
        connect: F,
    ) -> Result<Self>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(Postgres, Redis)>>,
    {
        local.prepare_witness_binding()?;
        let mut beginning = Beginning {
            local,
            finished: false,
        };
        tokio::time::timeout(std::time::Duration::from_secs(30), async move {
            let durable = control
                .acquire(deployment, selection, Uuid::new_v4())
                .await?;
            let observation = control.begin_store_observation(&durable).await?;
            let (primary, token) = connect().await?;
            let observed = observation.into_observed(primary, token).await?;
            let label = label(&durable);
            let owner = Arc::new(Owner {
                durable,
                observed,
                label,
                control: tokio::sync::Mutex::new(Some(control)),
            });
            beginning.local.bind_deployment(owner.clone())?;
            let work = Self {
                local: beginning.local.clone(),
                owner,
                completed: false,
            };
            beginning.finish();
            Ok(work)
        })
        .await
        .map_err(|_| Error::Deadline)?
    }

    pub fn admission(&self) -> &LocalAdmission {
        &self.local
    }

    pub async fn child<F, Fut>(
        &self,
        control: DeploymentControl,
        environment: Uuid,
        selection: &Selection,
        connect: F,
    ) -> Result<super::super::work::Work>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(Postgres, Redis)>>,
    {
        Self::child_admitted(&self.local, control, environment, selection, connect).await
    }

    pub(in crate::organizations::witness) async fn child_admitted<F, Fut>(
        local: &LocalAdmission,
        mut control: DeploymentControl,
        environment: Uuid,
        selection: &Selection,
        connect: F,
    ) -> Result<super::super::work::Work>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(Postgres, Redis)>>,
    {
        let owner = local.deployment_parent()?;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        tokio::time::timeout_at(
            deadline,
            control.check_child_selection(&owner.durable, environment, selection),
        )
        .await
        .map_err(|_| Error::Deadline)??;
        let mut beginning = Beginning {
            local: local.clone(),
            finished: false,
        };
        tokio::time::timeout_at(deadline, async move {
            let acquired = control
                .acquire_child(&owner.durable, environment, selection, Uuid::new_v4())
                .await;
            // The checked, single SQL statement has rolled back on an observed
            // PostgreSQL ERROR. No child exists, so the parent may finish its
            // own observations normally. Missing/malformed replies stay uncertain.
            if control.control.connection.is_some() && statement_refused(&acquired) {
                beginning.finish();
            }
            let durable = acquired?;
            let observation = control.control.begin_store_observation(&durable).await?;
            let (primary, token) = connect().await?;
            let observed = observation.into_observed(primary, token).await?;
            let history = Arc::new(super::super::work::HistoryOwner::with_observations(
                control.control,
                durable,
                Some(observed),
            ));
            let work = super::super::work::Work::from_parent(local, history)?;
            beginning.finish();
            Ok(work)
        })
        .await
        .map_err(|_| Error::Deadline)?
    }

    fn mark_completed(&mut self) {
        // Keep this Drop owner captured as a whole until completion succeeds.
        self.completed = true;
    }

    pub async fn complete(mut self) -> Result<State> {
        tokio::time::timeout(std::time::Duration::from_secs(30), async move {
            self.local.wait_for_exclusive_completion().await?;
            let state = self.owner.complete().await?;
            self.mark_completed();
            Ok(state)
        })
        .await
        .map_err(|_| Error::Deadline)?
    }

    /// A dropped response waiter does not abort actual work or parent completion.
    pub async fn execute<T, F>(self, future: F) -> Result<T>
    where
        T: Send + 'static,
        F: std::future::Future<Output = T> + Send + 'static,
    {
        let budget = self.local.execution_budget();
        tokio::spawn(async move {
            tokio::time::timeout(budget, async move {
                let result = self.local.store_scope(future).await?;
                self.complete().await?;
                Ok(result)
            })
            .await
            .map_err(|_| Error::Deadline)?
        })
        .await
        .map_err(|_| Error::Refused)?
    }
}

fn statement_refused(result: &Result<super::super::Admission>) -> bool {
    matches!(result, Err(Error::Storage(sqlx::Error::Database(error)))
        if error.try_downcast_ref::<sqlx::postgres::PgDatabaseError>()
            .is_some_and(|error| error.severity() == sqlx::postgres::PgSeverity::Error))
}

fn label(admission: &Admission) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let mut input = b"aegaeon-deployment-work-v1\0".to_vec();
    for id in [
        admission.deployment.0,
        admission.slot.epoch,
        admission.slot.worker_id,
    ] {
        input.extend_from_slice(id.as_bytes());
    }
    input.extend_from_slice(&admission.slot.slot.to_be_bytes());
    input.extend_from_slice(&admission.slot.generation.to_be_bytes());
    input.extend_from_slice(admission.slot.principal.as_bytes());
    URL_SAFE_NO_PAD.encode(aegaeon_crypto::hash::sha256_digest(&input))
}

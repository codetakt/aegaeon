use super::*;
use crate::organizations::{lifecycle::Runtime, witness::epoch::EpochBinding};
use uuid::Uuid;

pub(super) struct Binding {
    pub(super) runtime: Arc<Runtime>,
    pub(super) epoch: Option<EpochBinding>,
    pub(super) creation: Arc<Semaphore>,
}
impl Admission {
    /// Shared management metadata is protected by a real deployment or an
    /// already bound child. This is not an Environment authorization accessor.
    pub(crate) fn require_management_binding(&self) -> Result<(), sqlx::Error> {
        self.ensure_open()?;
        if self.current.is_some() {
            return self.require_store_scope();
        }
        #[cfg(test)]
        {
            if self.deployment.is_none() {
                self.epoch_binding()?;
            }
            self.require_store_scope()
        }
        #[cfg(not(test))]
        Err(sqlx::Error::Protocol(
            "selected runtime admission required".into(),
        ))
    }

    /// Bind an authenticated management request to one registered Environment.
    /// The child shares its parent's permit and failure state, but tracks its own
    /// retained SQL/response workers so completion never waits on the parent.
    pub(in crate::organizations) fn runtime_child(
        &self,
        runtime: &Arc<Runtime>,
        environment: Uuid,
    ) -> Result<Self, sqlx::Error> {
        self.require_store_scope()?;
        let binding = self.current.as_ref().ok_or(sqlx::Error::PoolClosed)?;
        if !Arc::ptr_eq(&binding.runtime, runtime)
            || binding.epoch.is_some()
            || !runtime.environments.contains_key(&environment)
        {
            return Err(sqlx::Error::Protocol("runtime child scope refused".into()));
        }
        let mut child = self.clone();
        child.ownership = Arc::new(());
        child.parent = Some(Arc::new(self.clone()));
        child.current = Some(Arc::new(Binding {
            runtime: runtime.clone(),
            epoch: Some(
                EpochBinding::current(environment, runtime.selection)
                    .map_err(|_| sqlx::Error::Protocol("invalid runtime Environment".into()))?,
            ),
            creation: binding.creation.clone(),
        }));
        Ok(child)
    }

    pub(in crate::organizations) fn for_runtime(
        runtime: Arc<Runtime>,
        limit: &Arc<Semaphore>,
        class: CapacityClass,
        environment: Option<Uuid>,
    ) -> Result<Self, sqlx::Error> {
        let mut local = Self::from_class(limit, class)?;
        let epoch = environment
            .map(|id| EpochBinding::current(id, runtime.selection))
            .transpose()
            .map_err(|_| sqlx::Error::Protocol("invalid runtime Environment".into()))?;
        local.current = Some(Arc::new(Binding {
            runtime,
            epoch,
            creation: Arc::new(Semaphore::new(1)),
        }));
        Ok(local)
    }

    pub(crate) fn current_runtime(&self) -> Result<Option<&Arc<Runtime>>, sqlx::Error> {
        self.ensure_open()?;
        Ok(self.current.as_ref().map(|binding| &binding.runtime))
    }
}

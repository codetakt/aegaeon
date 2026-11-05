use super::*;
use crate::organizations::witness::{deployment::work::Owner, work::HistoryOwner};

impl Admission {
    pub(in crate::organizations) fn deployment_parent(&self) -> Result<Arc<Owner>, sqlx::Error> {
        self.ensure_open()?;
        if self.witness.get().is_some() {
            return Err(sqlx::Error::Protocol(
                "deployment parent scope required".into(),
            ));
        }
        self.deployment
            .clone()
            .ok_or_else(|| sqlx::Error::Protocol("deployment admission required".into()))
    }

    pub(in crate::organizations) fn bind_deployment(
        &mut self,
        owner: Arc<Owner>,
    ) -> Result<(), sqlx::Error> {
        self.prepare_witness_binding()?;
        self.deployment = Some(owner);
        Ok(())
    }

    /// A child owns its own completion counter while retaining the real parent
    /// owner and its capacity lease. It cannot pass as the parent's ambient work.
    pub(in crate::organizations) fn child_with_history(
        &self,
        history: Arc<HistoryOwner>,
    ) -> Result<Self, sqlx::Error> {
        self.ensure_open()?;
        let parent = self.deployment.as_ref().ok_or(sqlx::Error::PoolClosed)?;
        if self.witness.get().is_some() || !parent.matches_child(history.admission()) {
            return Err(sqlx::Error::Protocol(
                "Organizations deployment child mismatch".into(),
            ));
        }
        let durable = history.admission();
        let witness = OnceLock::new();
        witness
            .set(WitnessBinding {
                epoch: durable.epoch_binding().clone(),
                store_label: durable.store_label(),
                history,
            })
            .map_err(|_| sqlx::Error::PoolClosed)?;
        Ok(Self {
            _permit: self._permit.clone(),
            ownership: Arc::new(()),
            limit: self.limit.clone(),
            class: self.class,
            parent: Some(Arc::new(self.clone())),
            witness: Arc::new(witness),
            deployment: self.deployment.clone(),
            started: Arc::new(AtomicBool::new(false)),
            current: None,
            failed: Arc::new(AtomicBool::new(false)),
        })
    }
}

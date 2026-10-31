//! Maintenance observation only. These records cannot complete an admission.
use super::{Control, Error, Result, Scope, State};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingWork {
    pub state: State,
    pub admissions: Vec<PendingAdmission>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingAdmission {
    pub environment_id: Uuid,
    pub slot: i32,
    pub generation: i64,
    pub pending: bool,
    pub epoch: Uuid,
    pub worker_id: Uuid,
    pub principal: String,
    #[serde(default)]
    pub store_label: String,
}

impl PendingWork {
    fn checked(mut self, scope: Scope) -> Result<Self> {
        let mut slots = HashSet::new();
        let mut workers = HashSet::new();
        if self.state.environment_id != scope.environment_id
            || self.state.deployment_id != scope.deployment_id
            || self.state.revision <= 0
            || self.state.operation_id.is_nil()
            || self.state.phase().is_err()
            || self.admissions.len() > 64
            || usize::try_from(self.state.pending).ok() != Some(self.admissions.len())
            || self.admissions.iter().any(|entry| {
                entry.environment_id != scope.environment_id
                    || !(0..64).contains(&entry.slot)
                    || entry.generation <= 0
                    || !entry.pending
                    || entry.epoch.is_nil()
                    || entry.worker_id.is_nil()
                    || entry.principal.is_empty()
                    || entry.principal.len() > 63
                    || entry.principal.contains('\0')
                    || !entry.store_label.is_empty()
                    || !slots.insert(entry.slot)
                    || !workers.insert(entry.worker_id)
            })
        {
            return Err(Error::Refused);
        }
        for entry in &mut self.admissions {
            entry.store_label = super::attribution::label(
                scope,
                entry.epoch,
                entry.worker_id,
                entry.slot,
                entry.generation,
                &entry.principal,
            );
        }
        Ok(self)
    }
}

impl Control {
    /// Observe the exact pending set with its current state. This neither drains
    /// a fence nor authorizes completion, recovery or a serving transition.
    pub async fn pending(&mut self, scope: Scope) -> Result<PendingWork> {
        self.maintenance()?;
        let observed: PendingWork = serde_json::from_value(
            self.value(
                sqlx::query_scalar("SELECT organization_witness.pending_work($1,$2)")
                    .bind(scope.environment_id)
                    .bind(scope.deployment_id),
            )
            .await?,
        )?;
        observed.checked(scope)
    }
}

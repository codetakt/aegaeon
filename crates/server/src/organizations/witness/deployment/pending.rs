use super::*;
use std::collections::HashSet;

/// Inspection metadata has no conversion to an executable admission.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingWork {
    pub state: State,
    admissions: Vec<Slot>,
}

impl DeploymentControl {
    pub async fn pending(&mut self, deployment: DeploymentId) -> Result<PendingWork> {
        self.control.maintenance()?;
        let result: PendingWork = serde_json::from_value(
            self.control
                .value(
                    sqlx::query_scalar("SELECT organization_witness.deployment_pending_work($1)")
                        .bind(deployment.0),
                )
                .await?,
        )?;
        State::decode(serde_json::to_value(&result.state)?, deployment)?;
        let mut slots = HashSet::new();
        let mut workers = HashSet::new();
        if result.admissions.len() > 64
            || usize::try_from(result.state.pending).ok() != Some(result.admissions.len())
            || result.admissions.iter().any(|slot| {
                slot.deployment_id != deployment.0
                    || !slot.pending
                    || !(0..64).contains(&slot.slot)
                    || slot.generation <= 0
                    || slot.epoch.is_nil()
                    || slot.worker_id.is_nil()
                    || slot.principal.is_empty()
                    || slot.principal.len() > 63
                    || slot.principal.contains('\0')
                    || !slots.insert(slot.slot)
                    || !workers.insert(slot.worker_id)
            })
        {
            return Err(Error::Refused);
        }
        Ok(result)
    }
}

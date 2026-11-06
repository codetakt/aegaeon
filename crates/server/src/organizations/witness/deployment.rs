//! Deployment ownership is distinct from Environment and user authorization.
//! Only the current v9 catalog can create these non-cloneable admissions.
#[cfg(test)]
use super::{Control, Error, Result, Role, Selection};
#[cfg(test)]
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::path::Path;
#[cfg(test)]
use uuid::Uuid;

#[cfg(test)]
pub mod configuration;
#[cfg(test)]
pub mod connector;
#[cfg(test)]
mod continuity;
pub mod dispatch;
#[cfg(test)]
mod lifecycle;
#[cfg(test)]
mod pending;
#[cfg(test)]
mod preflight;
#[cfg(test)]
pub mod progress;
#[cfg(test)]
pub mod work;

/// A selected identity, not an execution capability or an Environment sentinel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
pub struct DeploymentId(Uuid);

#[cfg(test)]
impl DeploymentId {
    pub fn new(value: Uuid) -> Result<Self> {
        if value.is_nil() {
            Err(Error::Refused)
        } else {
            Ok(Self(value))
        }
    }
    pub fn uuid(self) -> Uuid {
        self.0
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg(test)]
pub struct State {
    singleton: bool,
    pub deployment_id: Uuid,
    pub revision: i64,
    pub phase: String,
    pub operation_id: Uuid,
    pub epoch: Option<Uuid>,
    pub primary_id: Option<Uuid>,
    pub token_store_id: Option<Uuid>,
    pub source_sha256: Option<String>,
    pub history_sha256: Option<String>,
    pub acceptance_sha256: Option<String>,
    pub pending: u32,
}

#[cfg(test)]
impl State {
    fn decode(value: serde_json::Value, deployment: DeploymentId) -> Result<Self> {
        let state: Self = serde_json::from_value(value)?;
        if !state.singleton
            || state.deployment_id != deployment.0
            || state.revision <= 0
            || state.operation_id.is_nil()
            || state.pending > 64
            || !matches!(state.phase.as_str(), "active" | "fenced" | "prepared")
        {
            return Err(Error::Refused);
        }
        Ok(state)
    }

    fn selected(&self, selection: &Selection) -> bool {
        self.phase == "active"
            && self.epoch == Some(selection.epoch)
            && self.primary_id == Some(selection.primary)
            && self.token_store_id == Some(selection.token_store)
            && self.source_sha256.as_deref() == Some(selection.source_sha256.as_str())
            && self.history_sha256.as_deref() == Some(selection.history_sha256.as_str())
            && self.acceptance_sha256.as_deref() == Some(selection.acceptance_sha256.as_str())
    }
}

/// Dropping this handle never clears a durable slot. No public deserializer.
#[must_use]
#[cfg(test)]
pub struct Admission {
    deployment: DeploymentId,
    selection: Selection,
    slot: Slot,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg(test)]
struct Slot {
    deployment_id: Uuid,
    slot: i32,
    generation: i64,
    pending: bool,
    epoch: Uuid,
    worker_id: Uuid,
    principal: String,
}

#[cfg(test)]
pub struct DeploymentControl {
    control: Control,
}

#[cfg(test)]
impl DeploymentControl {
    /// Operator inspection/fencing keeps the verified current catalog. Individual
    /// Environment methods still enforce their own role and scope conditions.
    pub(super) fn environment_control(&mut self) -> &mut Control {
        &mut self.control
    }

    /// Environment provisioning remains maintenance-only and keeps its own
    /// explicit scope/epoch contract within the checked deployment catalog.
    pub fn environment_maintenance(&mut self) -> Result<&mut Control> {
        self.control.maintenance()?;
        Ok(&mut self.control)
    }

    pub(super) async fn checked(connection: sqlx::PgConnection, role: Role) -> Result<Self> {
        Ok(Self {
            control: Control::checked(connection, role).await?,
        })
    }
    pub async fn connect(endpoint: &str, ca: &Path, role: Role) -> Result<Self> {
        Ok(Self {
            control: Control::connect(endpoint, ca, role).await?,
        })
    }

    pub async fn close(self) -> Result<()> {
        self.control.close().await
    }

    pub async fn current(&mut self, deployment: DeploymentId) -> Result<State> {
        State::decode(
            self.control
                .value(
                    sqlx::query_scalar("SELECT organization_witness.deployment_state($1)")
                        .bind(deployment.0),
                )
                .await?,
            deployment,
        )
    }

    pub async fn acquire(
        &mut self,
        deployment: DeploymentId,
        selection: &Selection,
        worker: Uuid,
    ) -> Result<Admission> {
        if self.control.role != Role::Runtime
            || worker.is_nil()
            || [selection.epoch, selection.primary, selection.token_store]
                .iter()
                .any(Uuid::is_nil)
            || !self.current(deployment).await?.selected(selection)
        {
            return Err(Error::Refused);
        }
        let slot: Slot = serde_json::from_value(
            self.control
                .value(
                    sqlx::query_scalar(
                        "SELECT organization_witness.deployment_acquire($1,$2,$3,$4,$5)",
                    )
                    .bind(deployment.0)
                    .bind(selection.epoch)
                    .bind(selection.primary)
                    .bind(selection.token_store)
                    .bind(worker),
                )
                .await?,
        )?;
        if (slot.deployment_id, slot.epoch, slot.worker_id)
            != (deployment.0, selection.epoch, worker)
            || !slot.pending
            || !(0..64).contains(&slot.slot)
            || slot.generation <= 0
            || slot.principal.is_empty()
            || slot.principal.len() > 63
            || slot.principal.contains('\0')
        {
            return Err(Error::Refused);
        }
        Ok(Admission {
            deployment,
            selection: selection.clone(),
            slot,
        })
    }

    /// Requires actual worker/connection completion; the database also refuses
    /// unfinished store observation or any linked pending child generation.
    pub async fn complete(&mut self, admission: &Admission) -> Result<State> {
        if self.control.role != Role::Runtime {
            return Err(Error::Refused);
        }
        let slot = &admission.slot;
        State::decode(
            self.control
                .value(
                    sqlx::query_scalar(
                        "SELECT organization_witness.deployment_release($1,$2,$3,$4,$5)",
                    )
                    .bind(admission.deployment.0)
                    .bind(slot.slot)
                    .bind(slot.generation)
                    .bind(slot.epoch)
                    .bind(slot.worker_id),
                )
                .await?,
            admission.deployment,
        )
    }

    /// Acquires only the prepared child associated with this live parent.
    /// The enclosing work coordinator must retain the parent until child cleanup.
    pub(super) async fn acquire_child(
        &mut self,
        parent: &Admission,
        environment: Uuid,
        selection: &Selection,
        worker: Uuid,
    ) -> Result<super::Admission> {
        if self.control.role != Role::Runtime
            || worker.is_nil()
            || (selection.primary, selection.token_store)
                != (parent.selection.primary, parent.selection.token_store)
        {
            return Err(Error::Refused);
        }
        let scope = super::Scope {
            environment_id: environment,
            deployment_id: parent.deployment.0,
        };
        let binding = super::epoch::EpochBinding::selected(scope, selection)?;
        let slot = &parent.slot;
        let child: super::Slot = serde_json::from_value(self.control.value(
            sqlx::query_scalar("SELECT organization_witness.deployment_acquire_child($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
                .bind(parent.deployment.0).bind(slot.slot).bind(slot.generation).bind(slot.epoch)
                .bind(slot.worker_id).bind(environment).bind(selection.epoch)
                .bind(selection.primary).bind(selection.token_store).bind(worker),
        ).await?)?;
        if child.environment_id != environment
            || child.epoch != selection.epoch
            || child.worker_id != worker
            || child.principal != slot.principal
            || !child.pending
            || !(0..64).contains(&child.slot)
            || child.generation <= 0
        {
            return Err(Error::Refused);
        }
        Ok(super::Admission {
            binding,
            scope,
            slot: child,
        })
    }

    /// Read-only selection comparison before beginning child acquisition. The
    /// atomic acquisition still checks active epoch/store/parent association.
    pub(super) async fn check_child_selection(
        &mut self,
        parent: &Admission,
        environment: Uuid,
        selection: &Selection,
    ) -> Result<()> {
        let state = self
            .control
            .current(super::Scope {
                environment_id: environment,
                deployment_id: parent.deployment.0,
            })
            .await?;
        if state.environment_id != environment
            || state.deployment_id != parent.deployment.0
            || state.epoch != Some(selection.epoch)
            || state.primary_id != Some(selection.primary)
            || state.token_store_id != Some(selection.token_store)
            || state.source_sha256.as_deref() != Some(selection.source_sha256.as_str())
            || state.history_sha256.as_deref() != Some(selection.history_sha256.as_str())
            || state.acceptance_sha256.as_deref() != Some(selection.acceptance_sha256.as_str())
        {
            return Err(Error::Refused);
        }
        Ok(())
    }
}

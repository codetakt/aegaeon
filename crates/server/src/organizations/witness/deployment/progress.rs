//! Exact deployment checkpoints, separate from Environment observations.
use super::super::store_progress::{values, ObservedStores};
use super::super::{Error, Result, Role};
use super::{Admission, DeploymentControl, DeploymentId};
use crate::organizations::store_observation::{Postgres, Redis};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

/// Private operational evidence. It cannot construct an admission or selection.
#[derive(Debug, Serialize)]
pub struct Progress {
    checkpoint: Checkpoint,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    deployment_id: Uuid,
    epoch: Uuid,
    operation_id: Uuid,
    prepared_revision: i64,
    primary_id: Uuid,
    token_store_id: Uuid,
    primary_incarnation: Value,
    token_incarnation: Value,
    initial_wal: u64,
    wal_position: u64,
    principal: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    checkpoint: Checkpoint,
    observation: Observed,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observed {
    deployment_id: Uuid,
    slot: i32,
    generation: i64,
    epoch: Uuid,
    worker_id: Uuid,
    principal: String,
    minimum_wal: u64,
    finished_wal: Option<u64>,
}

/// Created by one live witness response, borrowed from that exact admission.
/// Loss never clears pending work. There is no Clone or deserialization path.
#[must_use]
pub struct Observation<'a> {
    admission: &'a Admission,
    record: Record,
}

impl Record {
    fn matches(&self, admission: &Admission) -> bool {
        let slot = &admission.slot;
        let beginning_is_retained = self.checkpoint.wal_position >= self.observation.minimum_wal;
        self.checkpoint.deployment_id == admission.deployment.0
            && self.checkpoint.epoch == slot.epoch
            && (self.checkpoint.primary_id, self.checkpoint.token_store_id)
                == (admission.selection.primary, admission.selection.token_store)
            && self.checkpoint.prepared_revision > 0
            && !self.checkpoint.operation_id.is_nil()
            && self.checkpoint.initial_wal <= self.checkpoint.wal_position
            && self.observation.deployment_id == admission.deployment.0
            && self.observation.slot == slot.slot
            && self.observation.generation == slot.generation
            && self.observation.epoch == slot.epoch
            && self.observation.worker_id == slot.worker_id
            && self.observation.principal == slot.principal
            && beginning_is_retained
    }
}

impl DeploymentControl {
    /// The caller owns the authenticated observed connections and a separately
    /// qualified prepared selection. Pinning alone never qualifies those stores.
    pub async fn pin_store_progress(
        &mut self,
        scope: DeploymentId,
        operation: Uuid,
        revision: i64,
        primary: &mut Postgres,
        token: &mut Redis,
    ) -> Result<Progress> {
        self.control.maintenance()?;
        let (mut observed_primary, observed_token) = values(primary, token).await?;
        let checkpoint: Checkpoint = serde_json::from_value(
            self.control
                .value(
                    sqlx::query_scalar(
                        "SELECT organization_witness.deployment_store_progress_pin($1,$2,$3,$4,$5)",
                    )
                    .bind(scope.0)
                    .bind(operation)
                    .bind(revision)
                    .bind(&observed_primary)
                    .bind(&observed_token),
                )
                .await?,
        )?;
        let position = observed_primary["wal_position"]
            .as_u64()
            .ok_or(Error::Refused)?;
        observed_primary
            .as_object_mut()
            .ok_or(Error::Refused)?
            .remove("wal_position");
        if checkpoint.deployment_id != scope.0
            || checkpoint.operation_id != operation
            || checkpoint.prepared_revision != revision
            || checkpoint.primary_incarnation != observed_primary
            || checkpoint.token_incarnation != observed_token
            || checkpoint.initial_wal > position
            || checkpoint.wal_position != checkpoint.initial_wal
            || checkpoint.epoch.is_nil()
            || checkpoint.primary_id.is_nil()
            || checkpoint.token_store_id.is_nil()
        {
            return Err(Error::Refused);
        }
        self.pin_continuity(scope, operation, revision, primary, token)
            .await?;
        Ok(Progress { checkpoint })
    }

    /// Capture the retained minimum before observing actual selected connections.
    /// A repeated begin refuses; a missing acknowledgement is not an unused slot.
    pub async fn begin_store_observation<'a>(
        &mut self,
        admission: &'a Admission,
    ) -> Result<Observation<'a>> {
        if self.control.role != Role::Runtime {
            return Err(Error::Refused);
        }
        let slot = &admission.slot;
        let record: Record = serde_json::from_value(
            self.control.value(
                sqlx::query_scalar(
                    "SELECT organization_witness.deployment_store_progress_begin($1,$2,$3,$4,$5)",
                )
                .bind(admission.deployment.0)
                .bind(slot.slot)
                .bind(slot.generation)
                .bind(slot.epoch)
                .bind(slot.worker_id),
            )
            .await?,
        )?;
        if !record.matches(admission) || record.observation.finished_wal.is_some() {
            return Err(Error::Refused);
        }
        Ok(Observation { admission, record })
    }
}

impl Observation<'_> {
    /// Record the actual observation once. This never completes its admission.
    /// All store work, cleanup and supplier checks remain the caller's duties.
    pub async fn record(
        self,
        control: &mut DeploymentControl,
        primary: &mut Postgres,
        token: &mut Redis,
    ) -> Result<Progress> {
        if control.control.role != Role::Runtime {
            return Err(Error::Refused);
        }
        let (primary, token) = values(primary, token).await?;
        finish(control, self.admission, &self.record, primary, token).await
    }
}

async fn finish(
    control: &mut DeploymentControl,
    admission: &Admission,
    record: &Record,
    mut primary: Value,
    token: Value,
) -> Result<Progress> {
    let slot = &admission.slot;
    let result: Record = serde_json::from_value(
        control.control
            .value(
                sqlx::query_scalar(
                    "SELECT organization_witness.deployment_store_progress_finish($1,$2,$3,$4,$5,$6,$7)",
                )
                .bind(admission.deployment.0)
                .bind(slot.slot)
                .bind(slot.generation)
                .bind(slot.epoch)
                .bind(slot.worker_id)
                .bind(&primary)
                .bind(&token),
            )
            .await?,
    )?;
    let position = primary["wal_position"].as_u64().ok_or(Error::Refused)?;
    primary
        .as_object_mut()
        .ok_or(Error::Refused)?
        .remove("wal_position");
    if !result.matches(admission)
        || result.observation.minimum_wal != record.observation.minimum_wal
        || result.observation.finished_wal != Some(position)
        || position < result.observation.minimum_wal
        || result.checkpoint.wal_position < position
        || result.checkpoint.primary_incarnation != primary
        || result.checkpoint.token_incarnation != token
        || result.checkpoint.primary_incarnation != record.checkpoint.primary_incarnation
        || result.checkpoint.token_incarnation != record.checkpoint.token_incarnation
    {
        return Err(Error::Refused);
    }
    Ok(Progress {
        checkpoint: result.checkpoint,
    })
}

pub(in crate::organizations::witness) struct DataObservations {
    record: Record,
    pub(in crate::organizations::witness) stores: Arc<ObservedStores>,
}
impl Observation<'_> {
    pub(in crate::organizations::witness) async fn into_observed(
        self,
        primary: Postgres,
        token: Redis,
    ) -> Result<Arc<DataObservations>> {
        let stores = ObservedStores::connect(
            self.record.checkpoint.primary_incarnation.clone(),
            self.record.checkpoint.token_incarnation.clone(),
            self.record.observation.minimum_wal,
            primary,
            token,
        )
        .await?;
        Ok(Arc::new(DataObservations {
            record: self.record,
            stores,
        }))
    }
}
impl DataObservations {
    pub(in crate::organizations::witness) async fn finish(
        &self,
        control: &mut DeploymentControl,
        admission: &Admission,
        previous_seal: Uuid,
        next_seal: Uuid,
    ) -> Result<()> {
        let (primary, token) = self
            .stores
            .finish_values_with_seal(admission.deployment.0, previous_seal, next_seal)
            .await?;
        finish(control, admission, &self.record, primary, token).await?;
        Ok(())
    }
}

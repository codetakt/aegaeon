//! Retained observations, not admission or nonrollback supplier qualification.
use super::{Admission, Control, Error, Result, Role, Scope};
use crate::organizations::store_observation::{Postgres, Redis};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

mod observed;
pub(in crate::organizations) use observed::DataObservations;
mod connections;
pub(in crate::organizations) use connections::ObservedStores;

/// Private operational evidence. It cannot construct an admission or selection.
#[derive(Debug, Serialize)]
pub struct Progress {
    checkpoint: Checkpoint,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    environment_id: Uuid,
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
    environment_id: Uuid,
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
        self.checkpoint.environment_id == admission.scope.environment_id
            && self.checkpoint.epoch == slot.epoch
            && Some((self.checkpoint.primary_id, self.checkpoint.token_store_id))
                == admission.binding.store_ids()
            && self.checkpoint.prepared_revision > 0
            && !self.checkpoint.operation_id.is_nil()
            && self.checkpoint.initial_wal <= self.checkpoint.wal_position
            && self.observation.environment_id == admission.scope.environment_id
            && self.observation.slot == slot.slot
            && self.observation.generation == slot.generation
            && self.observation.epoch == slot.epoch
            && self.observation.worker_id == slot.worker_id
            && self.observation.principal == slot.principal
            && beginning_is_retained
    }
}

pub(super) async fn values(primary: &mut Postgres, token: &mut Redis) -> Result<(Value, Value)> {
    let expected_primary = primary.observation().clone();
    primary
        .recheck(&expected_primary)
        .await
        .map_err(|_| Error::Refused)?;
    let expected_token = token.observation().clone();
    token
        .recheck(&expected_token)
        .await
        .map_err(|_| Error::Refused)?;
    Ok((
        serde_json::to_value(primary.observation())?,
        serde_json::to_value(token.observation())?,
    ))
}

impl Control {
    /// The caller owns the authenticated observed connections and a separately
    /// qualified prepared selection. Pinning alone never qualifies those stores.
    pub async fn pin_store_progress(
        &mut self,
        scope: Scope,
        operation: Uuid,
        revision: i64,
        primary: &mut Postgres,
        token: &mut Redis,
    ) -> Result<Progress> {
        self.maintenance()?;
        let (mut primary, token) = values(primary, token).await?;
        let checkpoint: Checkpoint = serde_json::from_value(
            self.value(
                sqlx::query_scalar(
                    "SELECT organization_witness.store_progress_pin($1,$2,$3,$4,$5,$6)",
                )
                .bind(scope.environment_id)
                .bind(scope.deployment_id)
                .bind(operation)
                .bind(revision)
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
        if checkpoint.environment_id != scope.environment_id
            || checkpoint.operation_id != operation
            || checkpoint.prepared_revision != revision
            || checkpoint.primary_incarnation != primary
            || checkpoint.token_incarnation != token
            || checkpoint.initial_wal > position
            || checkpoint.wal_position != checkpoint.initial_wal
            || checkpoint.epoch.is_nil()
            || checkpoint.primary_id.is_nil()
            || checkpoint.token_store_id.is_nil()
        {
            return Err(Error::Refused);
        }
        Ok(Progress { checkpoint })
    }

    /// Capture the retained minimum before observing actual selected connections.
    /// A repeated begin refuses; a missing acknowledgement is not an unused slot.
    pub async fn begin_store_observation<'a>(
        &mut self,
        admission: &'a Admission,
    ) -> Result<Observation<'a>> {
        if self.role != Role::Runtime {
            return Err(Error::Refused);
        }
        let slot = &admission.slot;
        let record: Record = serde_json::from_value(
            self.value(
                sqlx::query_scalar(
                    "SELECT organization_witness.store_progress_begin($1,$2,$3,$4,$5,$6)",
                )
                .bind(admission.scope.environment_id)
                .bind(admission.scope.deployment_id)
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
        control: &mut Control,
        primary: &mut Postgres,
        token: &mut Redis,
    ) -> Result<Progress> {
        if control.role != Role::Runtime {
            return Err(Error::Refused);
        }
        let (primary, token) = values(primary, token).await?;
        finish(control, self.admission, &self.record, primary, token).await
    }
}

async fn finish(
    control: &mut Control,
    admission: &Admission,
    record: &Record,
    mut primary: Value,
    token: Value,
) -> Result<Progress> {
    let slot = &admission.slot;
    let result: Record = serde_json::from_value(
        control
            .value(
                sqlx::query_scalar(
                    "SELECT organization_witness.store_progress_finish($1,$2,$3,$4,$5,$6,$7,$8)",
                )
                .bind(admission.scope.environment_id)
                .bind(admission.scope.deployment_id)
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

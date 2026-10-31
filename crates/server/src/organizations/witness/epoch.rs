//! Protected metadata, not a credential. Only comparison with an actual owned
//! witness admission gives this record its authority context.
use super::{Error, Result, Scope, Selection};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Record")]
pub struct EpochBinding {
    version: u32,
    environment_id: Uuid,
    deployment_id: Uuid,
    epoch: Uuid,
    primary_id: Uuid,
    token_store_id: Uuid,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    environment_id: Uuid,
    deployment_id: Uuid,
    epoch: Uuid,
    primary_id: Uuid,
    token_store_id: Uuid,
}
impl TryFrom<Record> for EpochBinding {
    type Error = Error;
    fn try_from(value: Record) -> Result<Self> {
        if value.version != 1
            || [
                value.environment_id,
                value.deployment_id,
                value.epoch,
                value.primary_id,
                value.token_store_id,
            ]
            .iter()
            .any(Uuid::is_nil)
        {
            return Err(Error::Refused);
        }
        Ok(Self {
            version: value.version,
            environment_id: value.environment_id,
            deployment_id: value.deployment_id,
            epoch: value.epoch,
            primary_id: value.primary_id,
            token_store_id: value.token_store_id,
        })
    }
}
impl EpochBinding {
    pub(crate) fn environment_id(&self) -> Uuid {
        self.environment_id
    }

    pub(super) fn selected(scope: Scope, selection: &Selection) -> Result<Self> {
        Record {
            version: 1,
            environment_id: scope.environment_id,
            deployment_id: scope.deployment_id,
            epoch: selection.epoch,
            primary_id: selection.primary,
            token_store_id: selection.token_store,
        }
        .try_into()
    }
    /// An equality check within the retained admission, not an offline currentness
    /// check. The caller must also validate its token, root, scope and current state.
    pub fn matches_admission(&self, work: &super::work::Work) -> bool {
        self.matches_owner(work.admission()) && self == work.binding()
    }

    /// Only a live-bound owner can authorize this comparison. Record shape and
    /// local capacity alone cannot establish an authority epoch.
    pub fn matches_owner(&self, owner: &crate::organizations::request_work::Admission) -> bool {
        owner.epoch_binding().is_ok_and(|binding| binding == self)
    }
}

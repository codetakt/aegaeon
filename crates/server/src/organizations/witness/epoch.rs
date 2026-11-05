//! Protected metadata, not a credential. Only comparison with an actual owned
//! witness admission gives this record its authority context.
use super::{Error, Result};
#[cfg(test)]
use super::{Scope, Selection};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Record")]
pub struct EpochBinding {
    version: u32,
    environment_id: Uuid,
    deployment_id: Uuid,
    epoch: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    primary_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_store_id: Option<Uuid>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    environment_id: Uuid,
    deployment_id: Uuid,
    epoch: Uuid,
    primary_id: Option<Uuid>,
    token_store_id: Option<Uuid>,
}
impl TryFrom<Record> for EpochBinding {
    type Error = Error;
    fn try_from(value: Record) -> Result<Self> {
        if !matches!(value.version, 1 | 2)
            || [value.environment_id, value.deployment_id, value.epoch]
                .iter()
                .any(Uuid::is_nil)
            || match value.version {
                1 => {
                    !matches!((value.primary_id,value.token_store_id), (Some(p),Some(t)) if !p.is_nil() && !t.is_nil())
                }
                2 => value.primary_id.is_some() || value.token_store_id.is_some(),
                _ => true,
            }
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
    #[cfg(test)]
    pub(super) fn store_ids(&self) -> Option<(Uuid, Uuid)> {
        self.primary_id.zip(self.token_store_id)
    }

    pub(in crate::organizations) fn current(
        environment: Uuid,
        selection: crate::organizations::lifecycle::Selection,
    ) -> Result<Self> {
        Record {
            version: 2,
            environment_id: environment,
            deployment_id: selection.deployment_id(),
            epoch: selection.generation(),
            primary_id: None,
            token_store_id: None,
        }
        .try_into()
    }

    pub(crate) fn environment_id(&self) -> Uuid {
        self.environment_id
    }

    #[cfg(test)]
    pub(super) fn selected(scope: Scope, selection: &Selection) -> Result<Self> {
        Record {
            version: 1,
            environment_id: scope.environment_id,
            deployment_id: scope.deployment_id,
            epoch: selection.epoch,
            primary_id: Some(selection.primary),
            token_store_id: Some(selection.token_store),
        }
        .try_into()
    }
    /// An equality check within the retained admission, not an offline currentness
    /// check. The caller must also validate its token, root, scope and current state.
    #[cfg(test)]
    pub fn matches_admission(&self, work: &super::work::Work) -> bool {
        self.matches_owner(work.admission()) && self == work.binding()
    }

    /// Only a live-bound owner can authorize this comparison. Record shape and
    /// local capacity alone cannot establish an authority epoch.
    pub fn matches_owner(&self, owner: &crate::organizations::request_work::Admission) -> bool {
        owner.epoch_binding().is_ok_and(|binding| binding == self)
    }
}

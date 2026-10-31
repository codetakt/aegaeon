use super::*;
use crate::organizations::{request_work::async_store, witness::epoch::EpochBinding};

pub(super) fn capture(scope: Scope) -> Result<EpochBinding, AuthorityError> {
    async_store::current_epoch_owner(scope.environment_id)
        .and_then(|owner| owner.epoch_binding().cloned())
        .map_err(|_| AuthorityError::Forbidden)
}

pub(super) fn require_current(authority: &Authority, scope: Scope) -> Result<(), AuthorityError> {
    require(authority.epoch.as_ref() == Some(&capture(scope)?))
}

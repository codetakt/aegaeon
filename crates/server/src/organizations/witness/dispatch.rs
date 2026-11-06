//! Shared finite capacity and periodic scheduling for the parent dispatcher.
use super::{work, Error, Result};
use crate::organizations::request_work::async_store;
#[cfg(test)]
use crate::organizations::request_work::{Admission, CapacityClass};

pub(super) mod periodic;

#[cfg(test)]
pub(super) fn acquire(class: CapacityClass) -> Result<Admission> {
    // Check the calling scope before spawning: Tokio child tasks do not inherit it.
    if async_store::task_owner()?.is_some() || tokio::runtime::Handle::try_current().is_err() {
        return Err(Error::Refused);
    }
    match class {
        CapacityClass::Ordinary => Admission::try_acquire(),
        CapacityClass::Revocation => Admission::try_acquire_revocation(),
        CapacityClass::Snapshot => Admission::try_acquire_snapshot(),
    }
    .map_err(|error| match error {
        sqlx::Error::PoolTimedOut => Error::CapacityExhausted,
        sqlx::Error::PoolClosed => Error::AdmissionClosed,
        other => other.into(),
    })
}

#[cfg(test)]
mod tests;

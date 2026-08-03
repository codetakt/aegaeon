#[cfg(test)]
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use thiserror::Error;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ParStateError {
    #[error("PAR state lock poisoned: {0}")]
    LockPoisoned(&'static str),
}

#[cfg(test)]
pub(super) fn try_read_lock<'a, T>(
    lock: &'a RwLock<T>,
    name: &'static str,
) -> Result<RwLockReadGuard<'a, T>, ParStateError> {
    lock.read().map_err(|err| {
        tracing::error!(error = %err, state = name, "PAR store read lock poisoned");
        ParStateError::LockPoisoned(name)
    })
}

#[cfg(test)]
pub(super) fn try_write_lock<'a, T>(
    lock: &'a RwLock<T>,
    name: &'static str,
) -> Result<RwLockWriteGuard<'a, T>, ParStateError> {
    lock.write().map_err(|err| {
        tracing::error!(error = %err, state = name, "PAR store write lock poisoned");
        ParStateError::LockPoisoned(name)
    })
}

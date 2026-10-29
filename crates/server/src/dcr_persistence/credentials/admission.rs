use std::{
    future::Future,
    sync::{Arc, LazyLock},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::super::DcrDatabaseError;

pub(super) const MAX_CREDENTIAL_UPDATES: usize = 2;
pub(super) static CREDENTIAL_UPDATES: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_CREDENTIAL_UPDATES)));

tokio::task_local! {
    static HTTP_UPDATE_ADMISSION: Arc<OwnedSemaphorePermit>;
}

fn acquire() -> Result<Arc<OwnedSemaphorePermit>, DcrDatabaseError> {
    CREDENTIAL_UPDATES
        .clone()
        .try_acquire_owned()
        .map(Arc::new)
        .map_err(|_| DcrDatabaseError::CredentialVerificationBusy)
}

// The scope starts outside all database-using HTTP middleware. All owner PUTs
// are admitted before reading a body or authenticating; no request data can
// select an unbounded bypass. Persistence shares this exact admission lease.
pub(crate) async fn admit_http_update<T>(
    request: impl Future<Output = T>,
) -> Result<T, DcrDatabaseError> {
    let admission = acquire()?;
    Ok(HTTP_UPDATE_ADMISSION.scope(admission, request).await)
}

pub(in crate::dcr_persistence) fn for_persistence(
    has_assertion: bool,
) -> Result<Option<Arc<OwnedSemaphorePermit>>, DcrDatabaseError> {
    if let Ok(admission) = HTTP_UPDATE_ADMISSION.try_with(Arc::clone) {
        return Ok(Some(admission));
    }
    has_assertion.then(acquire).transpose()
}

pub(crate) fn current() -> Option<Arc<OwnedSemaphorePermit>> {
    HTTP_UPDATE_ADMISSION.try_with(Arc::clone).ok()
}

/// A stopped or panicking owner cannot establish completed database cleanup.
pub(in crate::dcr_persistence) struct CompletionGuard {
    admission: Option<Arc<OwnedSemaphorePermit>>,
    finished: bool,
}

impl CompletionGuard {
    pub(in crate::dcr_persistence) fn new(admission: Option<Arc<OwnedSemaphorePermit>>) -> Self {
        Self {
            admission,
            finished: false,
        }
    }

    pub(in crate::dcr_persistence) fn complete(&mut self) {
        self.finished = true;
    }
}

impl Drop for CompletionGuard {
    fn drop(&mut self) {
        if !self.finished {
            if let Some(admission) = &self.admission {
                admission.semaphore().close();
            }
        }
    }
}

#[cfg(test)]
pub(in crate::dcr_persistence) async fn with_test_admission<T>(
    admission: Arc<OwnedSemaphorePermit>,
    request: impl Future<Output = T>,
) -> T {
    HTTP_UPDATE_ADMISSION.scope(admission, request).await
}

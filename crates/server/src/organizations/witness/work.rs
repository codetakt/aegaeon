//! Couples one durable admission to every retained primary-work owner. The
//! request worker must retain an Admission clone for token-store and other
//! detached work too; this component cannot infer their completion from SQL.
use super::Result;
#[cfg(test)]
use super::{Admission as DurableAdmission, Control, State};
use crate::organizations::request_work::Admission;
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use uuid::Uuid;

mod execution;
#[cfg(test)]
mod history;
#[cfg(test)]
mod observed;
#[cfg(test)]
pub(in crate::organizations) use history::HistoryOwner;
#[cfg(test)]
pub use observed::ObservedConnections;
mod http;
pub use execution::Execution;
pub(in crate::organizations) use execution::Starter;
pub use http::HttpExecution;
pub(crate) use http::ResponseLimit;

/// Dropping this owner never releases the durable slot. Completion is explicit
/// and requires all retained work/cleanup owners to have finished successfully.
#[must_use]
#[cfg(test)]
pub struct Work {
    local: Admission,
    history: Arc<HistoryOwner>,
    completed: bool,
}

#[cfg(test)]
impl Drop for Work {
    fn drop(&mut self) {
        if !self.completed {
            self.local.close_until_restart();
        }
    }
}

#[cfg(test)]
impl Work {
    pub(in crate::organizations::witness) fn from_parent(
        parent: &Admission,
        history: Arc<HistoryOwner>,
    ) -> Result<Self> {
        let local = parent.child_with_history(history.clone())?;
        Ok(Self {
            local,
            history,
            completed: false,
        })
    }
    /// Every detached worker must retain a clone, including workers that only
    /// use the token store. Connections also carry it through their cleanup.
    pub fn admission(&self) -> &Admission {
        &self.local
    }
    pub fn binding(&self) -> &super::epoch::EpochBinding {
        &self.history.durable.binding
    }
    pub fn epoch(&self) -> Uuid {
        self.history.durable.slot.epoch
    }
    /// Synchronous store facades and their driver threads inherit this owner.
    /// The closure must not start untracked child threads or async tasks.
    pub async fn blocking<T, F>(&self, function: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        self.local.blocking(function).await.map_err(Into::into)
    }
    /// Carry this admission through async token/code facades. Spawned tasks
    /// require their own explicit scope and retained admission.
    pub async fn store_scope<T>(&self, future: impl std::future::Future<Output = T>) -> Result<T> {
        self.local.store_scope(future).await.map_err(Into::into)
    }
    /// Run one finite operation to actual completion even if its response waiter
    /// disconnects. The result is exposed only after owned cleanup and durable
    /// completion. One 30-second deadline includes the operation, retained cleanup
    /// and control-store completion. Panic or uncertainty keeps admission pending.
    ///
    /// The future must include all store work, including any response streaming.
    /// Returning a lazy body or a future that will access stores is not a valid
    /// caller: this boundary cannot complete work that has not been performed.
    pub async fn execute<T, F>(self, future: F) -> Result<T>
    where
        T: Send + 'static,
        F: std::future::Future<Output = T> + Send + 'static,
    {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        tokio::spawn(async move {
            tokio::time::timeout_at(deadline, async move {
                let result = self.store_scope(future).await?;
                self.complete().await?;
                Ok(result)
            })
            .await
            .map_err(|_| super::Error::Deadline)?
        })
        .await
        .map_err(|_| super::Error::Refused)?
    }
    pub async fn complete(mut self) -> Result<State> {
        self.local.wait_for_exclusive_completion().await?;
        let state = self.history.complete().await?;
        self.completed = true;
        Ok(state)
    }
}

//! Couples one durable admission to every retained primary-work owner. The
//! request worker must retain an Admission clone for token-store and other
//! detached work too; this component cannot infer their completion from SQL.
use super::{Admission as DurableAdmission, Control, Result, Scope, Selection, State};
use crate::organizations::request_work::Admission;
use uuid::Uuid;

mod execution;
mod http;
pub use execution::Execution;
pub use http::HttpExecution;

/// Dropping this owner never releases the durable slot. Completion is explicit
/// and requires all retained work/cleanup owners to have finished successfully.
#[must_use]
pub struct Work {
    control: Option<Control>,
    local: Admission,
    durable: DurableAdmission,
    completed: bool,
}

struct Beginning {
    local: Admission,
    handed_off: bool,
}
impl Drop for Beginning {
    fn drop(&mut self) {
        if !self.handed_off {
            self.local.close_until_restart();
        }
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        if !self.completed {
            self.local.close_until_restart();
        }
    }
}

impl Work {
    /// The caller must acquire local capacity before opening its Control link,
    /// then enter this boundary before performing any selected-store work.
    pub async fn begin(
        mut control: Control,
        local: Admission,
        scope: Scope,
        selection: &Selection,
    ) -> Result<Self> {
        local.prepare_witness_binding()?;
        let mut beginning = Beginning {
            local,
            handed_off: false,
        };
        let durable = control.acquire(scope, selection, Uuid::new_v4()).await?;
        beginning.local.bind_witness(&durable)?;
        let work = Self {
            control: Some(control),
            local: beginning.local.clone(),
            durable,
            completed: false,
        };
        beginning.handed_off = true;
        Ok(work)
    }
    /// Every detached worker must retain a clone, including workers that only
    /// use the token store. Connections also carry it through their cleanup.
    pub fn admission(&self) -> &Admission {
        &self.local
    }
    pub fn binding(&self) -> &super::epoch::EpochBinding {
        &self.durable.binding
    }
    pub fn epoch(&self) -> Uuid {
        self.durable.slot.epoch
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
        let mut control = self.control.take().ok_or(super::Error::Refused)?;
        let result = control.complete(&self.durable).await;
        let close = control.close().await;
        let state = result?;
        close?;
        self.completed = true;
        Ok(state)
    }
}

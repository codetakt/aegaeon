//! Couples one durable admission to every retained primary-work owner. The
//! request worker must retain an Admission clone for token-store and other
//! detached work too; this component cannot infer their completion from SQL.
use super::{Admission as DurableAdmission, Control, Result, Scope, Selection, State};
use crate::organizations::request_work::Admission;
use uuid::Uuid;

/// Dropping this owner never releases the durable slot. Completion is explicit
/// and requires all retained work/cleanup owners to have finished successfully.
#[must_use]
pub struct Work {
    control: Control,
    local: Admission,
    durable: DurableAdmission,
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
        local.ensure_open()?;
        let durable = control.acquire(scope, selection, Uuid::new_v4()).await?;
        Ok(Self {
            control,
            local,
            durable,
        })
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
    pub async fn complete(mut self) -> Result<State> {
        self.local.wait_for_exclusive_completion().await?;
        let result = self.control.complete(&self.durable).await;
        let close = self.control.close().await;
        let state = result?;
        close?;
        Ok(state)
    }
}

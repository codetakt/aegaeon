use super::*;
use std::future::Future;

/// Dropping the response handle does not cancel the finite owned worker.
#[must_use]
pub struct Execution<T> {
    worker: tokio::task::JoinHandle<Result<T>>,
}

impl<T> Execution<T> {
    /// Observe the materialized result after actual durable completion.
    pub async fn result(self) -> Result<T> {
        self.worker
            .await
            .map_err(|_| super::super::Error::Refused)?
    }
}

struct Connecting {
    local: Option<Admission>,
}

impl Drop for Connecting {
    fn drop(&mut self) {
        if let Some(local) = &self.local {
            local.close_until_restart();
        }
    }
}

impl Work {
    /// Transfer fresh local capacity before the first control-store await.
    /// Spawning is synchronous: dropping the returned handle, even without
    /// polling it, cannot cancel acquisition or subsequent store completion.
    ///
    /// The connect future must only open the qualified independent runtime
    /// control link. No selected-store work may precede the operation future.
    /// The caller must already be inside Tokio; no fallback runtime is created.
    /// Qualification and streaming preconditions are the same as for `execute`.
    pub fn start<T, C, F>(
        local: Admission,
        scope: Scope,
        selection: Selection,
        connect: C,
        operation: F,
    ) -> Execution<T>
    where
        T: Send + 'static,
        C: Future<Output = Result<Control>> + Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        Self::start_until(local, scope, selection, connect, operation, deadline)
    }

    pub(super) fn start_until<T, C, F>(
        local: Admission,
        scope: Scope,
        selection: Selection,
        connect: C,
        operation: F,
        deadline: tokio::time::Instant,
    ) -> Execution<T>
    where
        T: Send + 'static,
        C: Future<Output = Result<Control>> + Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        let mut connecting = Connecting { local: Some(local) };
        let worker = tokio::spawn(async move {
            tokio::time::timeout_at(deadline, async move {
                connecting
                    .local
                    .as_ref()
                    .ok_or(super::super::Error::Refused)?
                    .prepare_witness_binding()?;
                let control = connect.await?;
                let local = connecting
                    .local
                    .take()
                    .ok_or(super::super::Error::Refused)?;
                let work = Work::begin(control, local, scope, &selection).await?;
                let result = work.store_scope(operation).await?;
                work.complete().await?;
                Ok(result)
            })
            .await
            .map_err(|_| super::super::Error::Deadline)?
        });
        Execution { worker }
    }
}

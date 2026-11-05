use super::*;
use std::future::Future;

/// Dropping the response handle does not cancel the finite owned worker.
#[must_use]
pub struct Execution<T> {
    worker: tokio::task::JoinHandle<Result<T>>,
}

/// A trusted constructor owns acquisition and scope before polling operation.
pub(in crate::organizations) trait Starter: Sized {
    /// Construct the operation only inside the admitted worker's scope.
    fn dispatch<T, F, Fut>(self, local: Admission, operation: F) -> Execution<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
    {
        let deadline = tokio::time::Instant::now() + local.execution_budget();
        self.start(local, async move { operation().await }, deadline)
    }

    fn start<T, F>(
        self,
        local: Admission,
        operation: F,
        deadline: tokio::time::Instant,
    ) -> Execution<T>
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static;
}

impl<T> Execution<T> {
    pub(in crate::organizations) fn from_worker(
        worker: tokio::task::JoinHandle<Result<T>>,
    ) -> Self {
        Self { worker }
    }
    /// Observe the materialized result after actual durable completion.
    pub async fn result(self) -> Result<T> {
        self.worker
            .await
            .map_err(|_| super::super::Error::Refused)?
    }
}

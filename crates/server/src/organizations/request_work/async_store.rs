//! Task-local propagation is explicit. Tokio child tasks never inherit it.
use super::Admission;
use std::future::Future;

tokio::task_local! {
    static CURRENT: Admission;
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum WorkerError {
    #[error("store worker failed: {0}")]
    Worker(#[from] tokio::task::JoinError),
    #[error("Organizations store admission unavailable: {0}")]
    Admission(#[from] sqlx::Error),
}

/// Capture the calling task's explicit admission before detaching its worker.
/// Ordinary callers outside an Organizations scope keep their existing path.
pub(crate) async fn blocking<T, F>(function: F) -> Result<T, WorkerError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    match CURRENT.try_with(Clone::clone) {
        Ok(owner) => owner.blocking(function).await.map_err(Into::into),
        Err(_) => tokio::task::spawn_blocking(function)
            .await
            .map_err(Into::into),
    }
}

impl Admission {
    pub(crate) fn require_store_scope(&self) -> Result<(), sqlx::Error> {
        self.ensure_open()?;
        if CURRENT
            .try_with(|owner| owner.same_work(self))
            .unwrap_or(false)
        {
            Ok(())
        } else {
            Err(sqlx::Error::Protocol(
                "missing or foreign Organizations store scope".into(),
            ))
        }
    }

    /// The future may call scoped async store facades. Any spawned task must
    /// carry this admission explicitly and enter its own scope.
    pub(crate) async fn store_scope<T>(
        &self,
        future: impl Future<Output = T>,
    ) -> Result<T, sqlx::Error> {
        self.start_store_work()?;
        if CURRENT.try_with(|_| ()).is_ok() {
            return Err(sqlx::Error::Protocol(
                "nested Organizations async store scope".into(),
            ));
        }
        struct Exit {
            owner: Admission,
            completed: bool,
        }
        impl Drop for Exit {
            fn drop(&mut self) {
                if !self.completed {
                    self.owner.close_until_restart();
                }
            }
        }
        let mut exit = Exit {
            owner: self.clone(),
            completed: false,
        };
        let result = CURRENT.scope(self.clone(), future).await;
        self.ensure_open()?;
        exit.completed = true;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn organizations_async_store_scope_isolates_tasks_and_retains_cancelled_workers() {
        let first = Admission::isolated_for_test().unwrap();
        let second = Admission::isolated_for_test().unwrap();
        assert!(first.require_store_scope().is_err());
        let (left, right) = tokio::join!(
            first.store_scope(async {
                tokio::task::yield_now().await;
                assert!(CURRENT.with(|owner| owner.same_work(&first)));
                assert!(first.require_store_scope().is_ok());
                assert!(second.require_store_scope().is_err());
                assert!(second.store_scope(async {}).await.is_err());
                assert!(tokio::spawn(async { CURRENT.try_with(|_| ()).is_err() })
                    .await
                    .unwrap());
                let nested = first.clone();
                blocking(move || crate::redis_io::organization::scope(nested, || ()).is_err())
                    .await
                    .unwrap()
            }),
            second.store_scope(async {
                tokio::task::yield_now().await;
                assert!(CURRENT.with(|owner| owner.same_work(&second)));
                17
            })
        );
        assert!(left.unwrap());
        assert_eq!(right.unwrap(), 17);
        assert!(CURRENT.try_with(|_| ()).is_err());
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::sync_channel(1);
        let owner = first.clone();
        let caller = tokio::spawn(async move {
            owner
                .store_scope(blocking(move || {
                    let _ = entered.send(());
                    wait.recv_timeout(std::time::Duration::from_secs(5))
                        .unwrap();
                }))
                .await
        });
        started.await.unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        assert!(first.ensure_open().is_err());
        assert!(
            std::sync::Arc::strong_count(&first._permit) > 1,
            "cancelled facade still owns its actual worker"
        );
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while std::sync::Arc::strong_count(&first._permit) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(first.ensure_open().is_err());
        assert!(second.ensure_open().is_ok());
        assert!(first.store_scope(async {}).await.is_err());
    }
}

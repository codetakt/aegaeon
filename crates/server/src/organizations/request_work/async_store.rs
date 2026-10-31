//! Task-local propagation is explicit. Tokio child tasks never inherit it.
use super::Admission;
use std::future::Future;

tokio::task_local! {
    static CURRENT: Admission;
}

/// Authority consumers require an explicit owner. Async tasks and synchronous
/// workers may expose it, but two different scopes cannot be combined.
pub(crate) fn current_owner() -> Result<Admission, sqlx::Error> {
    let task = CURRENT.try_with(Clone::clone).ok();
    let thread = crate::redis_io::organization::current_admission();
    let owner = match (task, thread) {
        (Some(task), Some(thread)) if task.same_work(&thread) => task,
        (Some(owner), None) | (None, Some(owner)) => owner,
        _ => {
            return Err(sqlx::Error::Protocol(
                "missing or conflicting Organizations owner".into(),
            ))
        }
    };
    owner.ensure_open()?;
    Ok(owner)
}

/// Obtain the already acquired owner before a consumer opens a primary link.
/// A second local permit would leave its SQL cleanup outside the witness.
pub(crate) fn current_epoch_owner(environment_id: uuid::Uuid) -> Result<Admission, sqlx::Error> {
    let owner = current_owner()?;
    if owner.epoch_binding()?.environment_id() != environment_id {
        return Err(sqlx::Error::Protocol(
            "foreign Organizations environment".into(),
        ));
    }
    Ok(owner)
}

/// A route may reuse only an explicitly entered task with the same epoch and
/// capacity class. Any existing but invalid scope refuses; there is no fallback.
pub(crate) fn route_owner(
    environment_id: uuid::Uuid,
    class: super::CapacityClass,
) -> Result<Option<Admission>, sqlx::Error> {
    match CURRENT.try_with(Clone::clone) {
        Ok(owner) => {
            let current = current_epoch_owner(environment_id)?;
            if !owner.same_work(&current) || owner.class != class {
                return Err(sqlx::Error::Protocol(
                    "foreign Organizations route capacity".into(),
                ));
            }
            Ok(Some(owner))
        }
        Err(_) if crate::redis_io::organization::current_admission().is_none() => Ok(None),
        Err(_) => Err(sqlx::Error::Protocol(
            "Organizations HTTP task scope required".into(),
        )),
    }
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
    match task_owner()? {
        Some(owner) => owner.blocking(function).await.map_err(Into::into),
        None => tokio::task::spawn_blocking(function)
            .await
            .map_err(Into::into),
    }
}

/// Explicit asynchronous callers may only use an absent or matching task scope.
pub(crate) fn task_owner() -> Result<Option<Admission>, sqlx::Error> {
    let task = CURRENT.try_with(Clone::clone).ok();
    let thread = crate::redis_io::organization::current_admission();
    let owner = match (task, thread) {
        (Some(owner), None) => Some(owner),
        (Some(owner), Some(thread)) if owner.same_work(&thread) => Some(owner),
        (None, None) => None,
        _ => {
            return Err(sqlx::Error::Protocol(
                "missing or conflicting Organizations async worker scope".into(),
            ))
        }
    };
    if let Some(owner) = &owner {
        owner.ensure_open()?;
    }
    Ok(owner)
}

/// Linearize a mutation with local admission closure. An already admitted
/// commit may finish afterward; the owner still retains its connection cleanup.
/// Ordinary callers outside either scope retain their existing behavior.
pub(crate) fn admit_current_commit() -> Result<(), sqlx::Error> {
    if let Some(owner) = task_owner()? {
        owner.admit_commit()?;
    }
    Ok(())
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
    async fn organizations_async_worker_refuses_thread_only_and_conflicting_scopes() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let outer = Admission::isolated_for_test().unwrap();
        let foreign = Admission::isolated_for_test().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        for conflicting in [false, true] {
            let inner = foreign.clone();
            let called = calls.clone();
            let refused = outer
                .blocking(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap();
                    runtime.block_on(async {
                        if conflicting {
                            inner
                                .store_scope(blocking(move || {
                                    called.fetch_add(1, Ordering::SeqCst)
                                }))
                                .await
                                .unwrap()
                                .is_err()
                        } else {
                            blocking(move || called.fetch_add(1, Ordering::SeqCst))
                                .await
                                .is_err()
                        }
                    })
                })
                .await
                .unwrap();
            assert!(
                refused,
                "scope conflict must refuse before detaching store work"
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(outer.ensure_open().is_ok() && foreign.ensure_open().is_ok());
        assert_eq!(
            blocking(|| 23).await.unwrap(),
            23,
            "ordinary unscoped behavior"
        );
    }

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

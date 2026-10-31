//! Actual isolated witness for caller tests, never a production qualification.
use super::*;
use crate::organizations::{request_work, witness::work::Work};
use std::future::{poll_fn, Future};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::task::Poll;

pub(crate) async fn with_scope<F, Fut>(function: F) -> TestResult
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = TestResult>,
{
    with_environment(Uuid::new_v4(), function()).await?
}

pub(crate) async fn with_environment<T>(
    environment_id: Uuid,
    future: impl Future<Output = T>,
) -> anyhow::Result<T> {
    anyhow::ensure!(!environment_id.is_nil());
    let fixture = Fixture::new().await?;
    let result = async {
        let mut maintenance = fixture.connect(Role::Maintenance).await?;
        let scope = Scope {
            environment_id,
            deployment_id: Uuid::new_v4(),
        };
        let selected = selection();
        let operation = Uuid::new_v4();
        maintenance.initialize(scope, operation).await?;
        maintenance.prepare(scope, operation, 1, &selected).await?;
        maintenance
            .activate(scope, operation, 2, &selected.acceptance_sha256)
            .await?;
        maintenance.close().await?;
        let work = Work::begin(
            fixture.connect(Role::Runtime).await?,
            request_work::Admission::isolated_for_test()?,
            scope,
            &selected,
        )
        .await?;
        // Catch a panic while polling borrowed test state, then drop the future
        // before actual fixture cleanup. Production scope/drop rules still run.
        let mut scoped = std::pin::pin!(async move {
            let result = work.store_scope(future).await?;
            anyhow::ensure!(work.complete().await?.pending == 0);
            Ok(result)
        });
        poll_fn(
            |context| match catch_unwind(AssertUnwindSafe(|| scoped.as_mut().poll(context))) {
                Ok(result) => result,
                Err(_) => Poll::Ready(Err(anyhow::anyhow!("witness-scoped test panicked"))),
            },
        )
        .await
    }
    .await;
    let cleanup = fixture.finish().await;
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

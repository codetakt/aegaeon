//! Actual isolated witness for caller tests, never a production qualification.
use super::caller_fixture::CallerFixture;
use super::*;
use std::future::{poll_fn, Future};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::task::Poll;

pub(crate) async fn with_scope<F, Fut>(function: F) -> TestResult
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = TestResult>,
{
    with_environment(
        Uuid::new_v4(),
        std::env::var("AEGAEON_DATABASE_URL")?.parse()?,
        function(),
    )
    .await?
}

pub(crate) fn with_environment<T>(
    environment_id: Uuid,
    primary: PgConnectOptions,
    future: impl Future<Output = T>,
) -> impl Future<Output = anyhow::Result<T>> {
    // Concurrent SQL operations make large debug-build futures. Box before
    // entering the witness wrappers so each wrapper carries only a pointer.
    // Poll on the same task to preserve the admission's task-local scope.
    let future = Box::pin(future);
    async move {
        anyhow::ensure!(!environment_id.is_nil());
        let mut fixture = CallerFixture::with_test_stores(environment_id, primary).await?;
        let result = {
            // Preserve panic cleanup while keeping actual data observations and
            // deployment ownership around every caller operation.
            let mut scoped = std::pin::pin!(async {
                let result = fixture.run(future).await?;
                anyhow::ensure!(fixture.pending().await? == 0);
                fixture.completed_parent_generation().await?;
                Ok(result)
            });
            poll_fn(|context| {
                match catch_unwind(AssertUnwindSafe(|| scoped.as_mut().poll(context))) {
                    Ok(result) => result,
                    Err(_) => Poll::Ready(Err(anyhow::anyhow!("witness-scoped test panicked"))),
                }
            })
            .await
        };
        let cleanup = fixture.finish().await;
        match (result, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }
}

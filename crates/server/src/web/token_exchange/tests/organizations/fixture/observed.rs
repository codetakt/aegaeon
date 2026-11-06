use super::*;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;
use std::future::{poll_fn, Future};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::task::Poll;

pub(in super::super) async fn in_epoch<T>(
    state: &AppState,
    future: impl Future<Output = TestResult<T>>,
) -> TestResult<T> {
    let witness = CallerFixture::with_observed_stores(
        state.environment_id,
        state.db_pool.connect_options().as_ref().clone(),
        redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?,
    )
    .await?;
    // Drop borrowed work before fixture cleanup, including an assertion panic.
    // The normal owner drop/uncertainty behavior remains in force.
    let result = {
        let mut scoped = std::pin::pin!(witness.run(future));
        poll_fn(
            |context| match catch_unwind(AssertUnwindSafe(|| scoped.as_mut().poll(context))) {
                Ok(result) => result,
                Err(_) => Poll::Ready(Err(anyhow::anyhow!("observed protocol test panicked"))),
            },
        )
        .await
    };
    let cleanup = witness.finish().await;
    let value = result?;
    cleanup?;
    value
}

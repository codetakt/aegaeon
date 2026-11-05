use super::*;

fn finite(
    starter: &deployment::Start,
    operation: impl Future<Output = Response> + Send + 'static,
) -> HttpExecution {
    HttpExecution::owned(
        starter.clone(),
        request_work::Admission::isolated_for_test().unwrap(),
        Method::GET,
        operation,
    )
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; finite HTTP bytes wait for completion and enforce representation bounds"]
async fn shared_redis_organizations_http_completion_finite_bytes_wait_and_bound() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let result = exercise(&mut fixture).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

async fn exercise(f: &mut Fixture) -> TestResult {
    let (mut maintenance, scope, starter) = super::super::admission_execution::active(f).await?;
    let (held, owner) = tokio::sync::oneshot::channel();
    let execution = finite(&starter, async move {
        Response::new(Body::new(LazyBody(Some(Box::pin(async move {
            let current = request_work::async_store::current_epoch_owner(scope.environment_id)
                .map_err(io::Error::other)?;
            let _ = held.send(current);
            Ok(Frame::data(Bytes::from_static(
                b"materialized token response",
            )))
        })))))
    });
    let owner = owner.await?;
    let mut response = Box::pin(execution.response());
    anyhow::ensure!(
        tokio::time::timeout(Duration::from_millis(100), response.as_mut())
            .await
            .is_err(),
        "no finite response before actual completion"
    );
    anyhow::ensure!(maintenance.current(scope).await?.pending == 1);
    drop(owner);
    let response = tokio::time::timeout(Duration::from_secs(5), response).await??;
    anyhow::ensure!(maintenance.current(scope).await?.pending == 0);
    anyhow::ensure!(
        axum::body::to_bytes(response.into_body(), 1024).await? == "materialized token response"
    );
    let max = crate::organizations::http_input::MAX_BODY_BYTES;
    for size in [max, max + 1] {
        let response = finite(&starter, async move {
            Response::new(Body::from(vec![b'x'; size]))
        })
        .response()
        .await;
        if size == max {
            anyhow::ensure!(
                axum::body::to_bytes(response?.into_body(), max)
                    .await?
                    .len()
                    == max
            );
        } else {
            anyhow::ensure!(response.is_err());
        }
        anyhow::ensure!(maintenance.current(scope).await?.pending == 0);
    }
    let response = finite(&starter, async move {
        Response::new(Body::new(LazyBody(Some(Box::pin(async move {
            let owner = request_work::async_store::current_epoch_owner(scope.environment_id)
                .map_err(io::Error::other)?;
            owner.close_until_restart();
            Ok(Frame::data(Bytes::from_static(b"must not be disclosed")))
        })))))
    })
    .response()
    .await;
    anyhow::ensure!(response.is_err());
    anyhow::ensure!(maintenance.current(scope).await?.pending == 1);
    anyhow::ensure!(super::super::admission_execution::parent_pending(f, scope).await? == 1);
    maintenance.close().await?;
    Ok(())
}

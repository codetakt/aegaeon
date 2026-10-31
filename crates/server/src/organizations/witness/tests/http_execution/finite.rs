use super::*;

fn finite(
    f: &Fixture,
    scope: Scope,
    selected: Selection,
    operation: impl Future<Output = Response> + Send + 'static,
) -> HttpExecution {
    let options = f
        .options
        .clone()
        .username(&f.runtime)
        .password(&f.runtime_password);
    Work::start_http(
        request_work::Admission::isolated_for_test().unwrap(),
        scope,
        selected,
        async move {
            Control::checked(PgConnection::connect_with(&options).await?, Role::Runtime).await
        },
        Method::GET,
        operation,
    )
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; finite HTTP bytes wait for completion and enforce representation bounds"]
async fn pg_organizations_http_completion_finite_bytes_wait_and_bound() -> TestResult {
    let fixture = Fixture::new().await?;
    let result = exercise(&fixture).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

async fn exercise(f: &Fixture) -> TestResult {
    let (mut maintenance, scope, selected) = super::super::admission_execution::active(f).await?;
    let (held, owner) = tokio::sync::oneshot::channel();
    let execution = finite(f, scope, selected.clone(), async move {
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
        let response = finite(f, scope, selected.clone(), async move {
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
    let response = finite(f, scope, selected, async move {
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
    maintenance.close().await?;
    Ok(())
}

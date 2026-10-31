use super::*;
use crate::organizations::{
    request_work,
    witness::work::{HttpExecution, Work},
};
use axum::{
    body::{Body, Bytes},
    http::{header, Method, StatusCode},
    response::Response,
};
use http_body::{Body as HttpBody, Frame};
use std::{
    future::{poll_fn, Future},
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use tokio::sync::Semaphore;

fn start(
    f: &Fixture,
    scope: Scope,
    selected: Selection,
    method: Method,
    operation: impl Future<Output = Response> + Send + 'static,
) -> HttpExecution {
    let options = f
        .options
        .clone()
        .username(&f.runtime)
        .password(&f.runtime_password);
    Work::start_http(
        request_work::Admission::isolated_class_for_test(request_work::CapacityClass::Snapshot)
            .unwrap(),
        scope,
        selected,
        async move {
            Control::checked(PgConnection::connect_with(&options).await?, Role::Runtime).await
        },
        method,
        operation,
    )
}

type Producing = Pin<Box<dyn Future<Output = io::Result<Frame<Bytes>>> + Send>>;
struct LazyBody(Option<Producing>);
impl HttpBody for LazyBody {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        let Some(producing) = &mut self.0 else {
            return Poll::Ready(None);
        };
        let result = std::task::ready!(producing.as_mut().poll(cx));
        self.0 = None;
        Poll::Ready(Some(result))
    }
}
async fn frame(body: &mut Body) -> Option<std::result::Result<Frame<Bytes>, axum::Error>> {
    poll_fn(|cx| Pin::new(&mut *body).poll_frame(cx)).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; lazy HTTP SQL and actual pool cleanup after response loss"]
async fn pg_organizations_http_completion_owns_lazy_sql_and_disconnect_cleanup() -> TestResult {
    let fixture = Fixture::new().await?;
    let result = lazy_sql(&fixture).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

async fn lazy_sql(f: &Fixture) -> TestResult {
    let (mut maintenance, scope, selected) = super::admission_execution::active(f).await?;
    for disconnect in [false, true] {
        let gate = Arc::new(Semaphore::new(0));
        let entered = Arc::new(AtomicBool::new(false));
        let (wait, seen) = (gate.clone(), entered.clone());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .after_release(move |_, _| {
                let (wait, seen) = (wait.clone(), seen.clone());
                Box::pin(async move {
                    seen.store(true, Ordering::SeqCst);
                    wait.acquire_owned().await.unwrap().forget();
                    Ok(true)
                })
            })
            .connect_lazy_with(f.options.clone());
        let source = pool.clone();
        let result = async {
            let response = start(f, scope, selected.clone(), Method::GET, async move {
                Response::builder()
                    .header(header::CONTENT_LENGTH, "2")
                    .body(Body::new(LazyBody(Some(Box::pin(async move {
                        let owner =
                            request_work::async_store::current_epoch_owner(scope.environment_id)
                                .map_err(io::Error::other)?;
                        let mut connection =
                            owner.connection(&source).await.map_err(io::Error::other)?;
                        let value: i32 = sqlx::query_scalar("SELECT 42")
                            .fetch_one(connection.as_mut().map_err(io::Error::other)?)
                            .await
                            .map_err(io::Error::other)?;
                        tokio::spawn(async move {
                            connection.release().await;
                        });
                        Ok(Frame::data(Bytes::from(value.to_string())))
                    })))))
                    .unwrap()
            })
            .response()
            .await?;
            anyhow::ensure!(!response.headers().contains_key(header::CONTENT_LENGTH));
            let mut body = response.into_body();
            let first = tokio::time::timeout(Duration::from_secs(5), frame(&mut body))
                .await?
                .ok_or_else(|| anyhow::anyhow!("missing frame"))??;
            anyhow::ensure!(first.into_data().unwrap() == "42");
            tokio::time::timeout(Duration::from_secs(5), async {
                while !entered.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await?;
            anyhow::ensure!(maintenance.current(scope).await?.pending == 1);
            anyhow::ensure!(
                tokio::time::timeout(Duration::from_millis(100), frame(&mut body))
                    .await
                    .is_err(),
                "end-of-body must wait for actual cleanup"
            );
            if disconnect {
                drop(body);
            } else {
                gate.add_permits(1);
                anyhow::ensure!(
                    tokio::time::timeout(Duration::from_secs(5), frame(&mut body))
                        .await?
                        .is_none()
                );
            }
            if disconnect {
                gate.add_permits(1);
            }
            tokio::time::timeout(Duration::from_secs(5), async {
                while maintenance.current(scope).await?.pending != 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Ok::<_, anyhow::Error>(())
            })
            .await??;
            Ok(())
        }
        .await;
        gate.add_permits(16);
        pool.close().await;
        result?;
    }
    maintenance.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; HTTP errors cannot become clean EOF after a buffered frame"]
async fn pg_organizations_http_completion_preserves_terminal_failure_and_trailers() -> TestResult {
    let fixture = Fixture::new().await?;
    let result = terminal(&fixture).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

async fn terminal(f: &Fixture) -> TestResult {
    let (mut maintenance, scope, selected) = super::admission_execution::active(f).await?;
    let response = start(f, scope, selected.clone(), Method::GET, async move {
        let mut trailers = axum::http::HeaderMap::new();
        trailers.insert("x-result", "complete".parse().unwrap());
        Response::new(Body::new(LazyBody(Some(Box::pin(async move {
            Ok(Frame::trailers(trailers))
        })))))
    })
    .response()
    .await?;
    let mut body = response.into_body();
    let trailers = frame(&mut body).await.unwrap()?.into_trailers().unwrap();
    anyhow::ensure!(trailers["x-result"] == "complete");
    anyhow::ensure!(frame(&mut body).await.is_none());
    anyhow::ensure!(maintenance.current(scope).await?.pending == 0);

    for trailer in [false, true] {
        let response = start(f, scope, selected.clone(), Method::GET, async move {
            Response::new(Body::new(LazyBody(Some(Box::pin(async move {
                let owner = request_work::async_store::current_epoch_owner(scope.environment_id)
                    .map_err(io::Error::other)?;
                owner.close_until_restart();
                Ok(if trailer {
                    Frame::trailers(axum::http::HeaderMap::new())
                } else {
                    Frame::data(Bytes::from_static(b"last frame"))
                })
            })))))
        })
        .response()
        .await?;
        let mut body = response.into_body();
        if !trailer {
            anyhow::ensure!(frame(&mut body).await.unwrap()?.into_data().unwrap() == "last frame");
        }
        anyhow::ensure!(
            frame(&mut body).await.is_some_and(|result| result.is_err()),
            "unconfirmed completion must not become clean EOF or terminal trailers"
        );
        anyhow::ensure!(maintenance.current(scope).await?.pending == if trailer { 2 } else { 1 });
    }
    maintenance.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; bodyless HTTP responses cannot publish before owned completion"]
async fn pg_organizations_http_completion_bodyless_waits_and_upgrade_refuses() -> TestResult {
    let fixture = Fixture::new().await?;
    let result = bodyless(&fixture).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

async fn bodyless(f: &Fixture) -> TestResult {
    let (mut maintenance, scope, selected) = super::admission_execution::active(f).await?;
    for (method, status) in [
        (Method::HEAD, StatusCode::OK),
        (Method::GET, StatusCode::NO_CONTENT),
        (Method::GET, StatusCode::NOT_MODIFIED),
    ] {
        let (held, owner) = tokio::sync::oneshot::channel();
        let execution = start(f, scope, selected.clone(), method, async move {
            let current =
                request_work::async_store::current_epoch_owner(scope.environment_id).unwrap();
            let _ = held.send(current);
            Response::builder()
                .status(status)
                .body(Body::empty())
                .unwrap()
        });
        let owner = owner.await?;
        let mut response = Box::pin(execution.response());
        anyhow::ensure!(
            tokio::time::timeout(Duration::from_millis(100), response.as_mut())
                .await
                .is_err()
        );
        anyhow::ensure!(maintenance.current(scope).await?.pending == 1);
        drop(owner);
        anyhow::ensure!(
            tokio::time::timeout(Duration::from_secs(5), response)
                .await??
                .status()
                == status
        );
        anyhow::ensure!(maintenance.current(scope).await?.pending == 0);
    }
    anyhow::ensure!(start(f, scope, selected, Method::GET, async {
        Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .body(Body::empty())
            .unwrap()
    })
    .response()
    .await
    .is_err());
    maintenance.close().await?;
    Ok(())
}

mod finite;

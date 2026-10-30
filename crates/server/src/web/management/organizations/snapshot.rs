//! One separately admitted snapshot; live authorization uses ordinary primary
//! transactions, never the older MVCC data connection.
use super::super::http_boundary::RequestContext;
use super::{boundary::failure, AppState};
use crate::organizations::{request_work::Admission, Scope};
use axum::{
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{header, HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    Extension,
};
use std::{io, time::Duration};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

mod worker;
use worker::Worker;

const LIFETIME: Duration = Duration::from_secs(3600);
const PROGRESS: Duration = Duration::from_secs(30);
type Item = Result<Bytes, io::Error>;
type Ready = oneshot::Sender<Result<(), Response>>;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NoQuery {}

pub(super) async fn export(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id)): Path<(Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    Query(_query): Query<NoQuery>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let worker = Worker {
        state,
        headers,
        admission,
        team,
        scope: Scope {
            environment_id,
            domain_id,
        },
        request_id: context.request_id.clone(),
    };
    if method == Method::HEAD {
        return match worker.authorize(None, None).await {
            Ok(_) => response(Body::empty()),
            Err(error) => error,
        };
    }
    let (sender, receiver) = mpsc::channel(1);
    let (ready, waiting) = oneshot::channel();
    tokio::spawn(run(worker, sender, Some(ready)));
    match waiting.await {
        Ok(Ok(())) => response(Body::from_stream(ReceiverStream::new(receiver))),
        Ok(Err(error)) => error,
        Err(_) => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            &context.request_id,
        ),
    }
}

fn response(body: Body) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/x-ndjson"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=organizations-snapshot.jsonl",
            ),
        ],
        body,
    )
        .into_response()
}

async fn run(worker: Worker, sender: mpsc::Sender<Item>, mut ready: Option<Ready>) {
    let deadline = tokio::time::Instant::now() + LIFETIME;
    let result = tokio::select! {
        () = sender.closed() => return,
        result = tokio::time::timeout_at(deadline, worker.transfer(&sender, &mut ready)) => result,
    };
    match result {
        Ok(Ok(())) => {}
        failure => {
            if let Some(ready) = ready {
                let response = match failure {
                    Ok(Err(error)) => error,
                    _ => worker.unavailable(),
                };
                let _ = ready.send(Err(response));
            }
            // A buffered prefix may remain. It never contains the terminal
            // manifest, and receivers must reject it even if this slot is full.
            let _ = sender.try_send(Err(io::Error::other("snapshot incomplete")));
        }
    }
}

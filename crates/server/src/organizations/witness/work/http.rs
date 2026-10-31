//! HTTP body polling stays inside the owned witness execution. Terminal success
//! follows cleanup and durable completion, never just a handler's return.
use super::*;
use axum::{
    body::{Body, Bytes},
    http::{header, response::Parts, Method, StatusCode},
    response::Response,
};
use http_body::{Body as HttpBody, Frame};
use std::{
    future::{poll_fn, Future},
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};

const PROGRESS: Duration = Duration::from_secs(20);
mod finite;

type Completion = Result<Option<Frame<Bytes>>>;

#[must_use]
pub struct HttpExecution {
    delivery: Delivery,
}

enum Delivery {
    Finite(Execution<Result<Response>>),
    Streaming(Streaming),
}

struct Streaming {
    head: oneshot::Receiver<(Parts, bool)>,
    frames: mpsc::Receiver<Frame<Bytes>>,
    completed: oneshot::Receiver<Completion>,
}

impl HttpExecution {
    pub async fn response(self) -> Result<Response> {
        match self.delivery {
            Delivery::Finite(execution) => execution.result().await?,
            Delivery::Streaming(streaming) => streaming.response().await,
        }
    }
}

impl Streaming {
    async fn response(self) -> Result<Response> {
        let (parts, bodyless) = self.head.await.map_err(|_| super::super::Error::Refused)?;
        if bodyless {
            self.completed
                .await
                .map_err(|_| super::super::Error::Refused)??;
            Ok(Response::from_parts(parts, Body::empty()))
        } else {
            Ok(Response::from_parts(
                parts,
                Body::new(CompletedBody {
                    frames: self.frames,
                    completed: self.completed,
                    done: false,
                }),
            ))
        }
    }
}

impl Work {
    /// Same qualified supplier and bounded-poll preconditions as `start`.
    /// The operation may return a lazy HTTP body; this worker polls it in scope.
    /// Response cancellation stops body polling but cannot cancel owned cleanup.
    pub fn start_http<C, F>(
        local: Admission,
        scope: Scope,
        selection: Selection,
        connect: C,
        method: Method,
        operation: F,
    ) -> HttpExecution
    where
        C: Future<Output = Result<Control>> + Send + 'static,
        F: Future<Output = Response> + Send + 'static,
    {
        if !local.is_snapshot() {
            return HttpExecution {
                delivery: Delivery::Finite(Self::start(
                    local,
                    scope,
                    selection,
                    connect,
                    async move { finite::materialize(operation.await, method).await },
                )),
            };
        }
        let deadline = tokio::time::Instant::now() + local.execution_budget();
        let (head, waiting) = oneshot::channel();
        let (sender, frames) = mpsc::channel(1);
        let (finished, completed) = oneshot::channel();
        let execution = Self::start_until(
            local,
            scope,
            selection,
            connect,
            async move {
                let response = operation.await;
                relay(response, method, head, sender).await
            },
            deadline,
        );
        tokio::spawn(async move {
            let result = execution.result().await.and_then(|result| result);
            let _ = finished.send(result);
        });
        HttpExecution {
            delivery: Delivery::Streaming(Streaming {
                head: waiting,
                frames,
                completed,
            }),
        }
    }
}

async fn relay(
    response: Response,
    method: Method,
    head: oneshot::Sender<(Parts, bool)>,
    sender: mpsc::Sender<Frame<Bytes>>,
) -> Completion {
    let (mut parts, mut body) = response.into_parts();
    if parts.status.is_informational() {
        return Err(super::super::Error::Refused);
    }
    let bodyless = method == Method::HEAD
        || matches!(
            parts.status,
            StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED
        );
    if !bodyless {
        // HTTP must observe the terminal frame/error, even if the producer
        // supplied an exact length. Hyper chooses the appropriate framing.
        parts.headers.remove(header::CONTENT_LENGTH);
    }
    if head.send((parts, bodyless)).is_err() || bodyless {
        return Ok(None);
    }
    let mut trailers = None;
    loop {
        let progress = async {
            let permit = sender
                .reserve()
                .await
                .map_err(|_| super::super::Error::Refused)?;
            match poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
                Some(Ok(frame)) => {
                    if trailers.is_some() {
                        return Err(super::super::Error::Refused);
                    }
                    if frame.is_trailers() {
                        trailers = Some(frame);
                    } else {
                        permit.send(frame);
                    }
                    Ok(true)
                }
                Some(Err(_)) => Err(super::super::Error::Refused),
                None => Ok(false),
            }
        };
        let more = tokio::select! {
            () = sender.closed() => return Ok(None),
            result = tokio::time::timeout(PROGRESS, progress) =>
                result.map_err(|_| super::super::Error::Deadline)??,
        };
        if !more {
            return Ok(trailers);
        }
    }
}

struct CompletedBody {
    frames: mpsc::Receiver<Frame<Bytes>>,
    completed: oneshot::Receiver<Completion>,
    done: bool,
}

impl HttpBody for CompletedBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        if self.done {
            return Poll::Ready(None);
        }
        match self.frames.poll_recv(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Some(frame)) => return Poll::Ready(Some(Ok(frame))),
            Poll::Ready(None) => {}
        }
        let result = std::task::ready!(Pin::new(&mut self.completed).poll(cx));
        self.done = true;
        Poll::Ready(match result {
            Ok(Ok(trailers)) => trailers.map(Ok),
            _ => Some(Err(io::Error::other("Organizations response incomplete"))),
        })
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }
}

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
mod budget;
mod finite;

#[derive(Clone, Copy)]
pub(crate) enum ResponseLimit {
    Organization,
    General,
}

impl ResponseLimit {
    fn bytes(self) -> usize {
        match self {
            Self::Organization => crate::organizations::http_input::MAX_BODY_BYTES,
            Self::General => 16 * 1024 * 1024,
        }
    }
}

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
    /// Defer closure construction as well as body polling until admission.
    pub(in crate::organizations::witness) fn dispatch<S, F, Fut>(
        starter: S,
        local: Admission,
        method: Method,
        limit: ResponseLimit,
        operation: F,
    ) -> Self
    where
        S: super::Starter,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Response> + Send + 'static,
    {
        Self::owned_with_limit(
            starter,
            local,
            method,
            limit,
            async move { operation().await },
        )
    }

    #[cfg(test)]
    pub(in crate::organizations::witness) fn owned<S, F>(
        starter: S,
        local: Admission,
        method: Method,
        operation: F,
    ) -> Self
    where
        S: super::Starter,
        F: Future<Output = Response> + Send + 'static,
    {
        Self::owned_with_limit(
            starter,
            local,
            method,
            ResponseLimit::Organization,
            operation,
        )
    }

    pub(in crate::organizations::witness) fn owned_with_limit<S, F>(
        starter: S,
        local: Admission,
        method: Method,
        limit: ResponseLimit,
        operation: F,
    ) -> Self
    where
        S: super::Starter,
        F: Future<Output = Response> + Send + 'static,
    {
        let deadline = tokio::time::Instant::now() + local.execution_budget();
        if !local.is_snapshot() {
            return Self {
                delivery: Delivery::Finite(starter.start(
                    local,
                    async move {
                        finite::materialize_bounded(operation.await, method, limit.bytes()).await
                    },
                    deadline,
                )),
            };
        }
        let (head, waiting) = oneshot::channel();
        let (sender, frames) = mpsc::channel(1);
        let (finished, completed) = oneshot::channel();
        let execution = starter.start(
            local,
            async move { relay(operation.await, method, head, sender).await },
            deadline,
        );
        tokio::spawn(async move {
            let _ = finished.send(execution.result().await.and_then(|result| result));
        });
        Self {
            delivery: Delivery::Streaming(Streaming {
                head: waiting,
                frames,
                completed,
            }),
        }
    }

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
                        let data = frame
                            .into_data()
                            .map_err(|_| super::super::Error::Refused)?;
                        permit.send(Frame::data(budget::copy(&data)?));
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

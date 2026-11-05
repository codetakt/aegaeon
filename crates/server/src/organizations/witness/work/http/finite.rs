//! Ordinary responses expose no bytes until actual owned completion. Buffering
//! is bounded by the same 64 KiB limit as Organizations API representations.
use super::*;
use axum::http::HeaderMap;
use std::collections::VecDeque;

pub(super) async fn materialize_bounded(
    response: Response,
    method: Method,
    limit: usize,
) -> Result<Response> {
    let (parts, mut body) = response.into_parts();
    if parts.status.is_informational() {
        return Err(super::super::super::Error::Refused);
    }
    if method == Method::HEAD
        || matches!(
            parts.status,
            StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED
        )
    {
        return Ok(Response::from_parts(parts, Body::empty()));
    }
    let mut bytes = VecDeque::new();
    let mut length = 0usize;
    let mut trailers = None;
    loop {
        let frame =
            tokio::time::timeout(PROGRESS, poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)))
                .await
                .map_err(|_| super::super::super::Error::Deadline)?;
        let Some(frame) = frame else {
            break;
        };
        let frame = frame.map_err(|_| super::super::super::Error::Refused)?;
        if trailers.is_some() {
            return Err(super::super::super::Error::Refused);
        }
        match frame.into_data() {
            Ok(data) => {
                if data.len() > limit - length {
                    return Err(super::super::super::Error::Refused);
                }
                length += data.len();
                if !data.is_empty() {
                    bytes.push_back(super::budget::copy(&data)?);
                }
            }
            Err(frame) => {
                trailers = Some(
                    frame
                        .into_trailers()
                        .map_err(|_| super::super::super::Error::Refused)?,
                )
            }
        }
        // Even an always-ready producer of empty frames must let the absolute
        // execution deadline run; bounded individual polls alone do not do so.
        tokio::task::yield_now().await;
    }
    Ok(Response::from_parts(
        parts,
        Body::new(Buffered { bytes, trailers }),
    ))
}

struct Buffered {
    bytes: VecDeque<Bytes>,
    trailers: Option<HeaderMap>,
}
impl HttpBody for Buffered {
    type Data = Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, Self::Error>>> {
        Poll::Ready(
            self.bytes
                .pop_front()
                .map(Frame::data)
                .or_else(|| self.trailers.take().map(Frame::trailers))
                .map(Ok),
        )
    }
    fn is_end_stream(&self) -> bool {
        self.bytes.is_empty() && self.trailers.is_none()
    }
}

//! Own the complete mounted browser operation before body or database admission.
use super::AppState;
use axum::{
    body::Body,
    extract::{MatchedPath, State},
    http::{Method, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::{Arc, LazyLock};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{instrument::WithSubscriber, Instrument};

const CAPACITY: usize = 8;
static OWNERS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(CAPACITY)));

fn unavailable(state: &AppState) -> Response {
    super::oauth_errors::no_cache_json_error_with_iss(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        None,
        &state.issuer,
    )
}

struct Owner {
    _permit: OwnedSemaphorePermit,
    finished: bool,
}
impl Owner {
    fn finish(&mut self) {
        self.finished = true;
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        if !self.finished {
            OWNERS.close();
        }
    }
}

pub(super) async fn capacity(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str);
    let applies = match route {
        Some("/authorize") => {
            matches!(*request.method(), Method::GET | Method::HEAD | Method::POST)
        }
        Some("/auth/consent") => request.method() == Method::POST,
        _ => false,
    };
    if !applies {
        return next.run(request).await;
    }
    let permit = match OWNERS.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return unavailable(&state),
    };
    let mut owner = Owner {
        _permit: permit,
        finished: false,
    };
    let worker = tokio::spawn(
        async move {
            let response = next.run(request).await;
            owner.finish();
            response
        }
        .in_current_span()
        .with_current_subscriber(),
    );
    // Timeout/disconnect drops only the handle; the running worker owns its
    // permit until the actual downstream operation has returned.
    match tokio::time::timeout(std::time::Duration::from_secs(30), worker).await {
        Ok(Ok(response)) => response,
        _ => unavailable(&state),
    }
}

#[cfg(test)]
pub(super) fn reserve_for_test() -> Result<OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
    OWNERS.clone().try_acquire_many_owned(CAPACITY as u32)
}

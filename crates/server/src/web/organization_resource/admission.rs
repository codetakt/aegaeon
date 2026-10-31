use super::*;
use crate::organizations::request_work::Admission;
use axum::{extract::MatchedPath, middleware::Next};

#[derive(Clone)]
pub(in crate::web) struct ResourceAdmission(pub Admission);

fn matched_route(request: &Request<Body>) -> bool {
    let Some(path) = request.extensions().get::<MatchedPath>() else {
        return false;
    };
    match path.as_str() {
        support::CREATE | support::REVOKE => *request.method() == Method::POST,
        support::READ => matches!(*request.method(), Method::GET | Method::HEAD),
        identity::PATH => matches!(*request.method(), Method::GET | Method::HEAD | Method::POST),
        delegated_invitations::ISSUE | delegated_invitations::REVOKE => {
            *request.method() == Method::POST
        }
        delegated_invitations::READ => matches!(*request.method(), Method::GET | Method::HEAD),
        invitations::CHALLENGE_PATH | invitations::ACCEPT_PATH => *request.method() == Method::POST,
        PATH | members::LIST_PATH => matches!(*request.method(), Method::GET | Method::HEAD),
        members::MEMBER_PATH => {
            matches!(*request.method(), Method::GET | Method::HEAD | Method::PUT)
        }
        _ => false,
    }
}

pub(in crate::web) fn admitted_route(request: &Request<Body>) -> bool {
    request.extensions().get::<ResourceAdmission>().is_some() && matched_route(request)
}

struct Worker {
    admission: Admission,
    finished: bool,
}

impl Worker {
    fn finish(&mut self) {
        self.finished = true;
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        if !self.finished {
            self.admission.close_until_restart();
        }
    }
}

pub(in crate::web) async fn capacity(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if !matched_route(&request) {
        return next.run(request).await;
    }
    let cancelling = request
        .extensions()
        .get::<MatchedPath>()
        .is_some_and(|path| {
            matches!(
                path.as_str(),
                delegated_invitations::REVOKE | support::REVOKE
            )
        });
    use crate::organizations::request_work::{async_store, CapacityClass};
    let class = if cancelling {
        CapacityClass::Revocation
    } else {
        CapacityClass::Ordinary
    };
    let admission = match async_store::route_owner(state.environment_id, class) {
        Ok(Some(owner)) => owner,
        Ok(None) => match if cancelling {
            Admission::try_acquire_revocation()
        } else {
            Admission::try_acquire()
        } {
            Ok(owner) => owner,
            Err(_) => return unavailable(&state),
        },
        Err(_) => return unavailable(&state),
    };
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    // Input-only work is cancellation safe: no store or worker owns this lease
    // yet. A disconnected or stalled reader must not close shared admission.
    let mut request = match read_empty_body(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    request
        .extensions_mut()
        .insert(ResourceAdmission(admission.clone()));
    let mut owner = Worker {
        admission,
        finished: false,
    };
    // Dropping the JoinHandle on response timeout/disconnect detaches the
    // worker. It still owns admission through all token-store and primary I/O.
    let worker_state = state.clone();
    let worker = tokio::spawn(async move {
        let response = owner.admission.store_scope(next.run(request)).await;
        owner.finish();
        response.unwrap_or_else(|_| unavailable(&worker_state))
    });
    match tokio::time::timeout_at(deadline, worker).await {
        Ok(Ok(response)) => response,
        _ => unavailable(&state),
    }
}

async fn read_empty_body(
    state: &AppState,
    request: Request<Body>,
) -> Result<Request<Body>, Response> {
    if !matches!(*request.method(), Method::GET | Method::HEAD) {
        return Ok(request);
    }
    let (parts, body) = request.into_parts();
    match tokio::time::timeout(
        std::time::Duration::from_secs(crate::organizations::http_input::BODY_TIMEOUT_SECONDS),
        to_bytes(body, 0),
    )
    .await
    {
        Ok(Ok(_)) => Ok(Request::from_parts(parts, Body::empty())),
        Ok(Err(_)) => {
            let mut response = error(state, StatusCode::BAD_REQUEST, "invalid_request");
            if parts
                .extensions
                .get::<MatchedPath>()
                .is_some_and(|p| p.as_str() == identity::PATH)
            {
                response
                    .headers_mut()
                    .remove(axum::http::header::WWW_AUTHENTICATE);
            }
            Err(response)
        }
        Err(_) => Err(unavailable(state)),
    }
}

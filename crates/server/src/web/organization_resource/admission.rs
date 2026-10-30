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
    mut request: Request<Body>,
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
    let admission = match if cancelling {
        Admission::try_acquire_revocation()
    } else {
        Admission::try_acquire()
    } {
        Ok(admission) => admission,
        Err(_) => return unavailable(&state),
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
    let worker = tokio::spawn(async move {
        let response = next.run(request).await;
        owner.finish();
        response
    });
    match tokio::time::timeout(std::time::Duration::from_secs(30), worker).await {
        Ok(Ok(response)) => response,
        _ => unavailable(&state),
    }
}

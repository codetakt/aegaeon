//! Explicit router fixture using the actual control store and HTTP coordinator.
//! Only tests construct this supplier; it is not production qualification.
use super::*;
use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::{from_fn_with_state, Next},
    response::{IntoResponse, Response},
    Router,
};
use std::sync::Arc;

type Classifier = fn(&Request<Body>) -> request_work::CapacityClass;

impl CallerFixture {
    pub(crate) fn router(self: &Arc<Self>, app: Router, classify: Classifier) -> Router {
        app.layer(from_fn_with_state((self.clone(), classify), admitted))
    }
}

async fn admitted(
    State((fixture, classify)): State<(Arc<CallerFixture>, Classifier)>,
    request: Request<Body>,
    next: Next,
) -> Response {
    use request_work::{Admission, CapacityClass};
    let local = match classify(&request) {
        CapacityClass::Ordinary => Admission::try_acquire(),
        CapacityClass::Revocation => Admission::try_acquire_revocation(),
        CapacityClass::Snapshot => Admission::try_acquire_snapshot(),
    };
    let Ok(local) = local else {
        return unavailable();
    };
    let method = request.method().clone();
    let execution = Work::start_http(
        local,
        fixture.scope,
        fixture.selected.clone(),
        async move { fixture.fixture.connect(Role::Runtime).await },
        method,
        async move { next.run(request).await },
    );
    execution.response().await.unwrap_or_else(|_| unavailable())
}

fn unavailable() -> Response {
    let mut response = (
        StatusCode::SERVICE_UNAVAILABLE,
        axum::Json(serde_json::json!({"error":"temporarily_unavailable"})),
    )
        .into_response();
    crate::util::apply_no_cache_headers(&mut response);
    response
}

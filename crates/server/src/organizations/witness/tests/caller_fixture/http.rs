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
    let execution = crate::organizations::witness::work::HttpExecution::owned(
        ObservedStart(fixture),
        local,
        method,
        async move { next.run(request).await },
    );
    execution.response().await.unwrap_or_else(|_| unavailable())
}

struct ObservedStart(Arc<CallerFixture>);
impl crate::organizations::witness::work::Starter for ObservedStart {
    fn start<T, F>(
        self,
        local: request_work::Admission,
        operation: F,
        deadline: tokio::time::Instant,
    ) -> crate::organizations::witness::work::Execution<T>
    where
        T: Send + 'static,
        F: std::future::Future<Output = T> + Send + 'static,
    {
        crate::organizations::witness::work::Execution::from_worker(tokio::spawn(async move {
            tokio::time::timeout_at(deadline, async move {
                let stores = &self.0.observed;
                let work = self.0.begin_observed(stores, local).await?;
                let result = work.store_scope(operation).await?;
                work.complete().await?;
                Ok(result)
            })
            .await
            .map_err(|_| Error::Deadline)?
        }))
    }
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

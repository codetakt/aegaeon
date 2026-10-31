use super::*;
use crate::organizations::request_work::async_store::blocking;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::sync::Semaphore;

static WORKERS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(8)));

fn unavailable(issuer: &str) -> Response {
    super::super::oauth_errors::no_cache_json_error_with_iss(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        Some("PAR storage capacity unavailable"),
        issuer,
    )
}

pub(super) async fn persist(state: AppState, request: crate::par::ParRequest) -> Response {
    let Ok(permit) = WORKERS.clone().try_acquire_owned() else {
        return unavailable(state.issuer.as_str());
    };
    let issuer = state.issuer.clone();
    let worker = blocking(move || {
        // Cancellation of the HTTP future cannot release this worker's slot.
        let _permit = permit;
        if let Err(response) = admit_par_request_object(&state, &request) {
            return response;
        }
        persist_admitted_par_request(&state, request)
    });
    match tokio::time::timeout(Duration::from_secs(30), worker).await {
        Ok(Ok(response)) => response,
        Ok(Err(_)) | Err(_) => unavailable(issuer.as_str()),
    }
}

#[cfg(test)]
pub(in crate::web) fn reserve_for_test(
) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
    WORKERS.clone().try_acquire_many_owned(8)
}

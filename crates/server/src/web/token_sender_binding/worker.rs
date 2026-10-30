use super::*;
use std::sync::{Arc, LazyLock};
use tokio::sync::Semaphore;

static PROOFS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(16)));

pub(in crate::web) async fn dpop_binding_from_request_async(
    dpop: &DpopMiddleware,
    role: DpopEndpointRole,
    method: &http::Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<Option<DpopBinding>, DpopError> {
    // Preserve malformed-header precedence and the no-proof fast path. Neither
    // case performs crypto, nonce or replay-store work.
    authorization_header(headers).map_err(|_| DpopError::InvalidProof)?;
    if dpop_header(headers)
        .map_err(|_| DpopError::InvalidProof)?
        .is_none()
    {
        return dpop_binding_from_request(dpop, role, method, uri, headers);
    }
    let permit = PROOFS.clone().try_acquire_owned().map_err(|_| {
        DpopError::BackendUnavailable("proof verification capacity unavailable".into())
    })?;
    let dpop = dpop.clone();
    let method = method.clone();
    let uri = uri.clone();
    let headers = headers.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        dpop_binding_from_request(&dpop, role, &method, &uri, &headers)
    })
    .await
    .map_err(|_| DpopError::BackendUnavailable("proof worker unavailable".into()))?
}

#[cfg(test)]
pub(in crate::web) fn reserve_for_test(
) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
    PROOFS.clone().try_acquire_many_owned(16)
}

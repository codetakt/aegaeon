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
    let owner = match crate::organizations::request_work::async_store::task_owner() {
        Ok(owner) => owner,
        Err(_) => return unavailable(&issuer),
    };
    let worker_issuer = issuer.clone();
    let worker = tokio::spawn(async move {
        let task = async {
            // This task retains the operation slot after HTTP cancellation.
            let _permit = permit;
            let prepared = blocking(move || {
                let jti = if state.protocol.par_store.uses_postgres() {
                    if let Some(claims) = request.request_object_claims.as_ref() {
                        let deps = super::super::authorize_context::authorize_request_object_deps(&state);
                        let context = super::super::authorize_request::request_object_jti_authorization_code_commit_context(&deps, &request.client_id, claims)
                            .map_err(|error| super::super::authorize_request::request_object_resolution_error_response(state.issuer.as_str(), &error))?;
                        Some(context.ok_or_else(|| unavailable(state.issuer.as_str()))?)
                    } else { None }
                } else {
                    admit_par_request_object(&state, &request)?;
                    None
                };
                Ok((state, request, jti))
            })
            .await;
            match prepared {
                Ok(Ok((state, request, jti))) => {
                    persist_admitted_par_request(&state, request, jti).await
                }
                Ok(Err(response)) => response,
                Err(_) => unavailable(&worker_issuer),
            }
        };
        match owner {
            Some(owner) => owner.store_scope(task).await.map_err(|_| ()),
            None => Ok(task.await),
        }
    });
    match tokio::time::timeout(Duration::from_secs(30), worker).await {
        Ok(Ok(Ok(response))) => response,
        Ok(Ok(Err(()))) | Ok(Err(_)) | Err(_) => unavailable(&issuer),
    }
}

#[cfg(test)]
pub(in crate::web) fn reserve_for_test(
) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
    WORKERS.clone().try_acquire_many_owned(8)
}

use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;

use crate::dcr_persistence::{DcrClientSecretChange, DcrDatabaseError};
use crate::runtime_restart::RuntimeRestartRequest;

use super::{no_cache_json_error_with_iss, AppState};

pub(super) fn dcr_disabled_response(issuer_base: &str) -> Response {
    no_cache_json_error_with_iss(StatusCode::NOT_FOUND, "not_found", None, issuer_base)
}

pub(super) fn dcr_database_context<'a>(
    state: &'a AppState,
    issuer_base: &str,
) -> Result<(&'a PgPool, &'a str), Response> {
    let pool = &state.db_pool;
    let issuer_host = state.runtime_authority.issuer_host().trim();
    if issuer_host.is_empty() {
        return Err(no_cache_json_error_with_iss(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            Some("dynamic client registration issuer scope is unavailable"),
            issuer_base,
        ));
    }
    Ok((pool, issuer_host))
}

pub(super) fn dcr_database_error_response(error: &DcrDatabaseError, issuer_base: &str) -> Response {
    tracing::error!(
        target: "dcr_database_registry",
        error = %error,
        "dynamic client registration database operation failed"
    );
    match error {
        DcrDatabaseError::ConcurrentModification => no_cache_json_error_with_iss(
            StatusCode::CONFLICT,
            "invalid_request",
            Some("dynamic client registration changed concurrently"),
            issuer_base,
        ),
        error if error.is_unique_violation() => no_cache_json_error_with_iss(
            StatusCode::CONFLICT,
            "invalid_request",
            Some("dynamic client registration conflicts with an existing client"),
            issuer_base,
        ),
        _ => no_cache_json_error_with_iss(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            Some("dynamic client registration database operation failed"),
            issuer_base,
        ),
    }
}

pub(super) fn dcr_database_secret_change(
    token_endpoint_auth_method: &str,
    generated_client_secret: Option<String>,
) -> DcrClientSecretChange {
    if crate::dcr_persistence::client_auth_method_uses_secret(token_endpoint_auth_method) {
        generated_client_secret.map_or(DcrClientSecretChange::Preserve, |secret| {
            DcrClientSecretChange::ReplaceWithPlaintext(secret)
        })
    } else {
        DcrClientSecretChange::RevokeAll
    }
}

fn request_restart_after_committed_runtime_sync_failure(
    state: &AppState,
    request_id: &str,
    issuer_host: &str,
    error: &crate::runtime_authority::RuntimeClientProjectionSyncError,
) {
    tracing::error!(
        target: "dcr_database_registry",
        request_id,
        issuer_host,
        database_committed = true,
        error = %error,
        "runtime client snapshot synchronization after dynamic client registration mutation failed; requesting graceful restart before serving stale client state"
    );
    state.runtime_restart.request_restart(
        RuntimeRestartRequest::runtime_client_projection_sync_failure(
            request_id.to_string(),
            issuer_host.to_string(),
            "dcr_database_registry",
        ),
    );
}

fn committed_runtime_sync_failure_response(issuer_base: &str) -> Response {
    no_cache_json_error_with_iss(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        Some("runtime client projection synchronization failed after database commit"),
        issuer_base,
    )
}

pub(super) async fn synchronize_dcr_database_runtime_clients(
    state: &AppState,
    issuer_base: &str,
    request_id: &str,
) -> Result<(), Response> {
    let (pool, issuer_host) = dcr_database_context(state, issuer_base)?;
    match state
        .runtime_authority
        .try_synchronize_client_projection_from_database(pool, state.clients.as_ref())
        .await
    {
        Ok(synchronized) => {
            let synchronized_client_count = synchronized.synchronized_client_count();
            tracing::debug!(
                target: "dcr_database_registry",
                issuer_host,
                count = synchronized_client_count,
                "runtime client snapshot synchronized after dynamic client registration mutation"
            );
            Ok(())
        }
        Err(error) => {
            request_restart_after_committed_runtime_sync_failure(
                state,
                request_id,
                issuer_host,
                &error,
            );
            Err(committed_runtime_sync_failure_response(issuer_base))
        }
    }
}

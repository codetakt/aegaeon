use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::runtime_configuration::{
    load_active_runtime_configuration_revision_for_issuer_host, RuntimeAuthorityRevision,
};
use crate::runtime_restart::{RuntimeRestartReason, RuntimeRestartRequest};

use super::{state::RuntimeAuthorityServices, AppState};

pub(super) async fn runtime_authority_guard_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if should_skip_runtime_authority_guard(req.uri().path()) {
        return next.run(req).await;
    }

    let runtime_authority_services = state.runtime_authority_services();
    if runtime_authority_services.runtime_restart.is_requested() {
        return runtime_restart_unavailable(&state);
    }
    if let Err(response) =
        ensure_runtime_authority_snapshot_is_current(&state, &runtime_authority_services).await
    {
        return response;
    }
    next.run(req).await
}

fn should_skip_runtime_authority_guard(path: &str) -> bool {
    matches!(path, "/health" | "/ready")
}

async fn ensure_runtime_authority_snapshot_is_current(
    state: &AppState,
    services: &RuntimeAuthorityServices,
) -> Result<(), Response> {
    let runtime_authority = &services.runtime_authority;
    if !runtime_authority.requires_runtime_request_admission() {
        return Ok(());
    }
    let issuer_host = runtime_authority.issuer_host();
    let loaded_revision = match runtime_authority.revision() {
        Ok(revision) => revision,
        Err(error) => {
            return request_restart_after_runtime_authority_state_failure(
                state,
                services,
                issuer_host,
                &error,
            );
        }
    };
    let current_revision = current_database_runtime_authority_revision_or_request_restart(
        state,
        services,
        issuer_host,
    )
    .await?;
    ensure_database_revision_matches_or_sync_client_projection(
        state,
        services,
        issuer_host,
        &loaded_revision,
        &current_revision,
    )
    .await
}

async fn current_database_runtime_authority_revision_or_request_restart(
    state: &AppState,
    services: &RuntimeAuthorityServices,
    issuer_host: &str,
) -> Result<RuntimeAuthorityRevision, Response> {
    match load_active_runtime_configuration_revision_for_issuer_host(&services.db_pool, issuer_host)
        .await
    {
        Ok(revision) => Ok(revision),
        Err(error) => request_restart_after_database_revision_read_failure(
            state,
            services,
            issuer_host,
            &error,
        ),
    }
}

async fn ensure_database_revision_matches_or_sync_client_projection(
    state: &AppState,
    services: &RuntimeAuthorityServices,
    issuer_host: &str,
    loaded_revision: &RuntimeAuthorityRevision,
    current_revision: &RuntimeAuthorityRevision,
) -> Result<(), Response> {
    if !loaded_revision.stable_authority_matches(current_revision) {
        return request_restart_after_database_runtime_authority_drift(
            state,
            services,
            issuer_host,
            loaded_revision,
            current_revision,
        );
    }

    if loaded_revision.active_runtime_client_fingerprint()
        != current_revision.active_runtime_client_fingerprint()
    {
        return synchronize_runtime_client_projection_or_request_restart(
            state,
            services,
            issuer_host,
            loaded_revision,
        )
        .await;
    }

    ensure_runtime_client_registry_matches_revision(state, services, issuer_host, loaded_revision)
}

fn ensure_runtime_client_registry_matches_revision(
    state: &AppState,
    services: &RuntimeAuthorityServices,
    issuer_host: &str,
    revision: &RuntimeAuthorityRevision,
) -> Result<(), Response> {
    let loaded_client_fingerprint = match services.clients.try_runtime_snapshot_fingerprint() {
        Ok(fingerprint) => fingerprint,
        Err(error) => {
            return request_restart_after_runtime_client_fingerprint_read_failure(
                state,
                services,
                issuer_host,
                &error,
            );
        }
    };
    if loaded_client_fingerprint.as_deref() == Some(revision.active_runtime_client_fingerprint()) {
        return Ok(());
    }
    request_restart_after_runtime_client_projection_mismatch(
        state,
        services,
        issuer_host,
        revision,
        loaded_client_fingerprint.as_deref(),
    )
}

fn request_restart_after_runtime_authority_state_failure(
    state: &AppState,
    services: &RuntimeAuthorityServices,
    issuer_host: &str,
    error: &crate::runtime_authority::RuntimeAuthorityStateError,
) -> Result<(), Response> {
    tracing::error!(
        target: "runtime_authority_guard",
        issuer_host,
        error = %error,
        "runtime authority state unavailable during request admission; requesting graceful restart to avoid serving stale runtime state"
    );
    request_admission_unavailable_restart(services, issuer_host, "runtime_authority_state");
    Err(runtime_restart_unavailable(state))
}

fn request_restart_after_database_revision_read_failure(
    state: &AppState,
    services: &RuntimeAuthorityServices,
    issuer_host: &str,
    error: &crate::runtime_configuration::RuntimeConfigurationError,
) -> Result<RuntimeAuthorityRevision, Response> {
    tracing::error!(
        target: "runtime_authority_guard",
        issuer_host,
        error = %error,
        "runtime authority database revision unavailable during request admission; requesting graceful restart to avoid serving stale runtime state"
    );
    request_admission_unavailable_restart(services, issuer_host, "runtime_authority_database");
    Err(runtime_restart_unavailable(state))
}

fn request_restart_after_database_runtime_authority_drift(
    state: &AppState,
    services: &RuntimeAuthorityServices,
    issuer_host: &str,
    loaded_revision: &RuntimeAuthorityRevision,
    current_revision: &RuntimeAuthorityRevision,
) -> Result<(), Response> {
    tracing::error!(
        target: "runtime_authority_guard",
        issuer_host,
        loaded_configuration_version_id = %loaded_revision.active_configuration_version_id(),
        active_configuration_version_id = %current_revision.active_configuration_version_id(),
        configuration_document_changed = loaded_revision.active_configuration_document_fingerprint()
            != current_revision.active_configuration_document_fingerprint(),
        runtime_key_set_changed = loaded_revision.active_runtime_key_set_fingerprint()
            != current_revision.active_runtime_key_set_fingerprint(),
        dcr_bearer_token_changed = loaded_revision.active_dcr_bearer_token_fingerprint()
            != current_revision.active_dcr_bearer_token_fingerprint(),
        "runtime authority database revision drift detected during request admission; requesting graceful restart before serving runtime-critical drift"
    );
    request_admission_drift_restart(services, issuer_host, "runtime_authority_database");
    Err(runtime_restart_unavailable(state))
}

async fn synchronize_runtime_client_projection_or_request_restart(
    state: &AppState,
    services: &RuntimeAuthorityServices,
    issuer_host: &str,
    loaded_revision: &RuntimeAuthorityRevision,
) -> Result<(), Response> {
    tracing::warn!(
        target: "runtime_authority_guard",
        issuer_host,
        configuration_version_id = %loaded_revision.active_configuration_version_id(),
        "runtime client projection changed during request admission; synchronizing issuer-scoped client snapshot"
    );
    match services
        .runtime_authority
        .try_synchronize_client_projection_from_database_from(
            &services.db_pool,
            loaded_revision,
            services.clients.as_ref(),
        )
        .await
    {
        Ok(synchronized) => ensure_runtime_client_registry_matches_revision(
            state,
            services,
            issuer_host,
            synchronized.authority_revision(),
        ),
        Err(error) => {
            tracing::error!(
                target: "runtime_authority_guard",
                issuer_host,
                configuration_version_id = %loaded_revision.active_configuration_version_id(),
                error = %error,
                "runtime client projection synchronization failed during request admission; requesting graceful restart to avoid serving stale client state"
            );
            services.runtime_restart.request_restart(
                RuntimeRestartRequest::runtime_client_projection_sync_failure(
                    "runtime-authority-guard",
                    issuer_host.to_string(),
                    "runtime_client_projection",
                ),
            );
            Err(runtime_restart_unavailable(state))
        }
    }
}

fn request_restart_after_runtime_client_fingerprint_read_failure(
    state: &AppState,
    services: &RuntimeAuthorityServices,
    issuer_host: &str,
    error: &crate::client_registry::ClientRegistryStateError,
) -> Result<(), Response> {
    tracing::error!(
        target: "runtime_authority_guard",
        issuer_host,
        error = %error,
        "runtime client snapshot fingerprint unavailable during request admission; requesting graceful restart to avoid serving stale client state"
    );
    request_admission_unavailable_restart(services, issuer_host, "runtime_client_fingerprint");
    Err(runtime_restart_unavailable(state))
}

fn request_restart_after_runtime_client_projection_mismatch(
    state: &AppState,
    services: &RuntimeAuthorityServices,
    issuer_host: &str,
    revision: &RuntimeAuthorityRevision,
    loaded_client_fingerprint: Option<&str>,
) -> Result<(), Response> {
    tracing::error!(
        target: "runtime_authority_guard",
        issuer_host,
        active_configuration_version_id = %revision.active_configuration_version_id(),
        active_runtime_client_fingerprint = revision.active_runtime_client_fingerprint(),
        loaded_runtime_client_fingerprint = loaded_client_fingerprint,
        "runtime client projection is inconsistent during request admission; requesting graceful restart to avoid serving stale client state"
    );
    request_admission_drift_restart(services, issuer_host, "runtime_client_projection");
    Err(runtime_restart_unavailable(state))
}

fn request_admission_unavailable_restart(
    services: &RuntimeAuthorityServices,
    issuer_host: &str,
    surface: &'static str,
) {
    services
        .runtime_restart
        .request_restart(RuntimeRestartRequest::runtime_authority_unavailable(
            "runtime-authority-guard",
            issuer_host.to_string(),
            surface,
        ));
}

fn request_admission_drift_restart(
    services: &RuntimeAuthorityServices,
    issuer_host: &str,
    surface: &'static str,
) {
    services
        .runtime_restart
        .request_restart(RuntimeRestartRequest::runtime_authority_drift(
            "runtime-authority-guard",
            issuer_host.to_string(),
            surface,
        ));
}

fn runtime_restart_unavailable(state: &AppState) -> Response {
    super::json_error_with_iss(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        Some(runtime_restart_description(state)),
        state.issuer.as_str(),
    )
    .into_response()
}

fn runtime_restart_description(state: &AppState) -> &'static str {
    match state
        .runtime_restart
        .request()
        .map(|request| request.reason())
    {
        Some(RuntimeRestartReason::RuntimeCriticalMutation { .. }) => {
            "runtime restart requested after runtime-critical management mutation"
        }
        Some(RuntimeRestartReason::RuntimeClientProjectionSyncFailure { .. }) => {
            "runtime restart requested after runtime client projection synchronization failure"
        }
        Some(RuntimeRestartReason::RuntimeAuthorityDrift { .. }) => {
            "runtime restart requested after runtime-authority drift"
        }
        Some(RuntimeRestartReason::RuntimeAuthorityUnavailable { .. }) => {
            "runtime restart requested because runtime authority is unavailable"
        }
        None => "runtime restart requested",
    }
}

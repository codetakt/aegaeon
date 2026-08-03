use super::{dcr_configuration, local_auth, local_auth_recovery, management, metadata, AppState};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    middleware::{self as axum_middleware},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};

use crate::runtime_configuration::load_active_runtime_configuration_revision_for_issuer_host;

use super::state::RUNTIME_AUTHORITY_DATABASE_REVISION_CACHE_TTL;

const SERVER_REQUEST_BODY_LIMIT_BYTES: usize = 2 * 1024 * 1024;

pub fn build_router(state: AppState) -> Router {
    let management_router = management::router(state.management.clone());
    let transport_state = state.clone();
    let runtime_authority_state = state.clone();
    let router = Router::new()
        .nest("/api/v1", management_router)
        .route("/health", get(health))
        .route("/ready", get(readiness))
        .route(
            "/.well-known/oauth-authorization-server",
            get(metadata::well_known_oauth_authorization_server),
        )
        .route(
            "/.well-known/openid-configuration",
            get(metadata::well_known_openid_configuration),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(metadata::well_known_oauth_protected_resource),
        )
        .route("/jwks", get(metadata::jwks))
        .route("/.well-known/jwks.json", get(metadata::jwks))
        .route("/register", post(super::register))
        .route(
            "/register/:client_id",
            get(dcr_configuration::register_read)
                .put(dcr_configuration::register_update)
                .delete(dcr_configuration::register_delete),
        )
        .route(
            "/oauth/upstream/:connection/authorize",
            get(super::upstream_authorize),
        )
        .route(
            "/oauth/upstream/:connection/callback",
            get(super::upstream_callback),
        )
        .route(
            "/oauth/upstream/logout/callback",
            get(super::upstream_logout_callback),
        )
        .route("/oauth/upstream/refresh", post(super::upstream_refresh))
        .route(
            "/auth/login",
            get(local_auth::local_login_get).post(local_auth::local_login_post),
        )
        .route(
            "/auth/activate",
            get(local_auth_recovery::local_activate_get)
                .post(local_auth_recovery::local_activate_post),
        )
        .route(
            "/auth/password/reset",
            get(local_auth_recovery::local_password_reset_get)
                .post(local_auth_recovery::local_password_reset_post),
        )
        .route("/auth/logout", post(local_auth::local_logout_post))
        .route("/authorize", get(super::authorize))
        .route("/token", post(super::token))
        .route("/par", post(super::par))
        .route("/resource", get(super::resource))
        .route("/introspect", post(super::introspect))
        .route("/revoke", post(super::revoke))
        .route(
            "/userinfo",
            get(super::userinfo_get).post(super::userinfo_post),
        )
        .route("/logout", get(super::logout))
        .fallback(not_found);
    mount_device_routes_if_enabled(router, &state)
        .layer(DefaultBodyLimit::max(SERVER_REQUEST_BODY_LIMIT_BYTES))
        .layer(axum_middleware::from_fn_with_state(
            runtime_authority_state,
            super::runtime_authority_guard_middleware,
        ))
        .layer(axum_middleware::from_fn_with_state(
            transport_state,
            super::transport_security_middleware,
        ))
        .with_state(state)
}

fn mount_device_routes_if_enabled(router: Router<AppState>, state: &AppState) -> Router<AppState> {
    if !state.cfg.grant_runtime().device_authorization_enabled() {
        return router;
    }
    router
        .route("/device_authorization", post(super::device_authorization))
        .route(
            "/device",
            get(super::device_verify_get).post(super::device_verify_post),
        )
        .route("/device/approve", post(super::device_approve))
        .route("/device/deny", post(super::device_deny))
}

async fn health() -> &'static str {
    "OK"
}

async fn readiness(State(state): State<AppState>) -> Response {
    if state.runtime_restart.is_requested() {
        return readiness_unavailable(&state, "runtime restart requested");
    }
    let runtime_authority_services = state.runtime_authority_services();
    let issuer_host = runtime_authority_services.runtime_authority.issuer_host();
    let loaded_revision = match runtime_authority_services.runtime_authority.revision() {
        Ok(revision) => revision,
        Err(_) => {
            return readiness_unavailable(&state, "runtime authority revision is unavailable");
        }
    };
    let current_revision = match runtime_authority_services.readiness.current_revision() {
        Some(revision) => revision,
        None => match load_active_runtime_configuration_revision_for_issuer_host(
            &runtime_authority_services.db_pool,
            issuer_host,
        )
        .await
        {
            Ok(revision) => {
                runtime_authority_services.readiness.store_revision(
                    revision.clone(),
                    RUNTIME_AUTHORITY_DATABASE_REVISION_CACHE_TTL,
                );
                revision
            }
            Err(_) => {
                return readiness_unavailable(
                    &state,
                    "runtime authority database revision is unavailable",
                );
            }
        },
    };
    if !loaded_revision.stable_authority_matches(&current_revision) {
        return readiness_unavailable(&state, "runtime stable authority revision is stale");
    }
    if loaded_revision.active_runtime_client_fingerprint()
        != current_revision.active_runtime_client_fingerprint()
    {
        return readiness_unavailable(&state, "runtime authority client projection is stale");
    }

    let loaded_client_fingerprint = match runtime_authority_services
        .clients
        .try_runtime_snapshot_fingerprint()
    {
        Ok(fingerprint) => fingerprint,
        Err(_) => {
            return readiness_unavailable(
                &state,
                "runtime client projection fingerprint is unavailable",
            );
        }
    };
    if loaded_client_fingerprint.as_deref()
        != Some(current_revision.active_runtime_client_fingerprint())
    {
        return readiness_unavailable(&state, "runtime client projection revision is stale");
    }

    StatusCode::NO_CONTENT.into_response()
}

fn readiness_unavailable(state: &AppState, description: &'static str) -> Response {
    super::json_error_with_iss(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        Some(description),
        state.issuer.as_str(),
    )
}

async fn not_found(State(state): State<AppState>) -> Response {
    super::json_error_with_iss(
        StatusCode::NOT_FOUND,
        "not_found",
        None,
        state.issuer.as_str(),
    )
}

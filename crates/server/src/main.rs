#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(deprecated))]
use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tracing::info;

use aegaeon_observability::metrics::OAuthMetrics;
use prometheus::Registry;

use aegaeon_server::config::{BootstrapConfig, RuntimeStateNamespace, ServerConfig};
use aegaeon_server::db::{connect_required_pool, preflight_required_schema_revision};
use aegaeon_server::dcr_persistence::preflight_dynamic_registration_schema;
#[cfg(test)]
use aegaeon_server::kms::{KeyManager, KeyManagerError};
use aegaeon_server::metrics_integration::MetricsIntegration;
use aegaeon_server::middleware::tls::TransportSecurity;
use aegaeon_server::oidc::{OidcConfig, OidcSessionStore};
use aegaeon_server::runtime_authority::RuntimeAuthorityState;
use aegaeon_server::runtime_configuration::DatabaseRuntimeConfiguration;
use aegaeon_server::runtime_fatal::terminate_runtime;
use aegaeon_server::runtime_restart::RuntimeRestartState;
use aegaeon_server::web::build_router;
use aegaeon_server::web::management::ManagementState;
use aegaeon_server::web::AppState as ServerAppState;

#[path = "main/app_state.rs"]
mod app_state;
#[path = "main/background_tasks.rs"]
mod background_tasks;
#[path = "main/bootstrap_env.rs"]
mod bootstrap_env;
#[path = "main/browser_auth_runtime.rs"]
mod browser_auth_runtime;
#[path = "main/client_runtime.rs"]
mod client_runtime;
#[path = "main/dcr_runtime.rs"]
mod dcr_runtime;
#[path = "main/device_runtime.rs"]
mod device_runtime;
#[path = "main/dpop.rs"]
mod dpop;
#[path = "main/federation_runtime.rs"]
mod federation_runtime;
#[path = "main/oidc_runtime.rs"]
mod oidc_runtime;
#[path = "main/protocol_runtime.rs"]
mod protocol_runtime;
#[path = "main/runtime_config.rs"]
mod runtime_config;
#[path = "main/runtime_key_managers.rs"]
mod runtime_key_managers;
#[path = "main/sync_runtime.rs"]
mod sync_runtime;
#[path = "main/token_runtime.rs"]
mod token_runtime;
#[path = "main/upstream_runtime.rs"]
mod upstream_runtime;

use app_state::{app_state_from_parts, AppStateParts};
use background_tasks::{
    spawn_cleanup_task, spawn_runtime_authority_notification_listener_task,
    spawn_runtime_config_monitor_task,
};
use bootstrap_env::runtime_issuer_host_from_env;
#[cfg(test)]
use bootstrap_env::{env_flag, env_num, env_optional_non_empty, env_optional_trimmed};
use browser_auth_runtime::browser_auth_runtime_for_authority;
use client_runtime::client_registry_for_runtime_authority;
use dcr_runtime::dcr_runtime_for_authority;
use device_runtime::device_runtime_stores_from_shared_env;
use dpop::dpop_middleware_from_shared_store_env;
use federation_runtime::federation_runtime_for_authority;
use oidc_runtime::{
    effective_issuer, oidc_sessions_from_shared_env, userinfo_endpoint_for_oidc_runtime,
};
use protocol_runtime::protocol_runtime_stores_from_shared_env;
use runtime_config::{
    hydrate_database_runtime_config, log_runtime_state_boundary, oidc_runtime_from_authority,
    runtime_issuer_for_authority, validate_runtime_boundaries_for_authority,
};
use runtime_key_managers::runtime_key_managers;
#[cfg(test)]
use runtime_key_managers::DisabledKeyManager;
use sync_runtime::{prepare_runtime_sync_for_authority, RuntimeSyncPlan};
use token_runtime::token_runtime_from_shared_env;
use upstream_runtime::upstream_runtime_for_authority;

#[derive(Parser, Debug)]
#[command(name = "aegaeon-server")]
#[command(about = "OAuth 2.x Authorization Server", long_about = None)]
struct Args {
    /// Host to bind to
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Port to bind to
    #[arg(short, long, default_value = "8080")]
    port: u16,
}

struct BuiltServerRuntime {
    state: ServerAppState,
    database_runtime_config: DatabaseRuntimeConfiguration,
    runtime_sync: RuntimeSyncPlan,
}

struct RuntimeAuthority {
    oidc_runtime: Option<Arc<OidcConfig>>,
    oidc_sessions: Option<OidcSessionStore>,
    issuer: String,
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();
}

fn log_startup(args: &Args) {
    info!("Starting Aegaeon identity provider");
    info!("Listening on {}:{}", args.host, args.port);
}

fn register_metrics() -> Result<(Arc<Registry>, Arc<MetricsIntegration>)> {
    let registry = Arc::new(Registry::new());
    let oauth_metrics = Arc::new(OAuthMetrics::new(&registry)?);
    let metrics = Arc::new(MetricsIntegration::new(oauth_metrics));
    MetricsIntegration::register_global(&metrics);
    Ok((registry, metrics))
}

fn startup_runtime_issuer_host() -> Result<String> {
    let issuer_host = runtime_issuer_host_from_env()?;
    info!("Runtime issuer host selector {}", issuer_host);
    Ok(issuer_host)
}

async fn hydrate_database_runtime(
    bootstrap_config: BootstrapConfig,
    issuer_host: &str,
) -> Result<(ServerConfig, sqlx::PgPool, DatabaseRuntimeConfiguration)> {
    let db_pool = connect_required_pool(bootstrap_config.database()).await?;
    preflight_required_schema_revision(&db_pool).await?;
    info!("PostgreSQL schema revision preflight completed");
    preflight_dynamic_registration_schema(&db_pool).await?;
    info!("Dynamic client registration database schema preflight completed");
    let (server_config, database_runtime_config) =
        hydrate_database_runtime_config(bootstrap_config, &db_pool, issuer_host).await?;
    Ok((server_config, db_pool, database_runtime_config))
}

async fn runtime_authority(
    server_config: &ServerConfig,
    database_runtime_config: &DatabaseRuntimeConfiguration,
    runtime_state_namespace: &RuntimeStateNamespace,
) -> Result<RuntimeAuthority> {
    let runtime_issuer = runtime_issuer_for_authority(database_runtime_config);
    let oidc_runtime =
        oidc_runtime_from_authority(&runtime_issuer, database_runtime_config).await?;
    validate_runtime_boundaries_for_authority(
        server_config,
        oidc_runtime.is_some(),
        database_runtime_config,
    )?;
    log_runtime_state_boundary(server_config);

    let oidc_sessions =
        oidc_sessions_from_shared_env(oidc_runtime.as_deref(), runtime_state_namespace)?;
    let issuer = effective_issuer(&runtime_issuer, oidc_runtime.as_deref());
    Ok(RuntimeAuthority {
        oidc_runtime,
        oidc_sessions,
        issuer,
    })
}

fn runtime_issuer_host(database_runtime_config: &DatabaseRuntimeConfiguration) -> Arc<String> {
    Arc::new(database_runtime_config.issuer_host.clone())
}

#[expect(
    clippy::too_many_lines,
    reason = "existing server bootstrap orchestration; new oversized functions remain gated"
)]
async fn build_server_runtime(_args: &Args) -> Result<BuiltServerRuntime> {
    let startup_issuer_host = startup_runtime_issuer_host()?;
    let bootstrap_config = BootstrapConfig::try_from_env()?;
    let (server_config, db_pool, database_runtime_config) =
        hydrate_database_runtime(bootstrap_config, &startup_issuer_host).await?;
    let runtime_state_namespace =
        RuntimeStateNamespace::from_environment_id(database_runtime_config.environment_id);
    let base_url = database_runtime_config.issuer_url.clone();
    let database_runtime_policy = &database_runtime_config.state.policy;
    let authority = runtime_authority(
        &server_config,
        &database_runtime_config,
        &runtime_state_namespace,
    )
    .await?;
    let RuntimeAuthority {
        oidc_runtime,
        oidc_sessions,
        issuer,
    } = authority;

    let (registry, metrics) = register_metrics()?;
    let transport_security = TransportSecurity::new(server_config.transport.clone());
    let cfg = Arc::new(server_config);

    let clients = Arc::new(client_registry_for_runtime_authority(
        database_runtime_policy,
        cfg.as_ref(),
        &runtime_state_namespace,
    )?);

    let protocol_runtime = protocol_runtime_stores_from_shared_env(
        cfg.as_ref(),
        metrics.clone(),
        &runtime_state_namespace,
    )?;

    let runtime_keys = &database_runtime_config.runtime_keys;
    let (key_manager, jwt_introspection_key_manager) =
        runtime_key_managers(cfg.as_ref(), runtime_keys)?;
    let token_runtime = token_runtime_from_shared_env(
        cfg.as_ref(),
        key_manager.clone(),
        oidc_runtime.as_deref(),
        oidc_sessions.clone(),
        &issuer,
        &runtime_state_namespace,
    )?;

    let dpop_middleware = Arc::new(dpop_middleware_from_shared_store_env(
        cfg.as_ref(),
        &issuer,
        &runtime_state_namespace,
    )?);

    let runtime_authority_revision = database_runtime_config.authority_revision()?;
    let runtime_authority_state = RuntimeAuthorityState::from_database_revision(
        runtime_issuer_host(&database_runtime_config),
        runtime_authority_revision,
    );
    let runtime_sync = prepare_runtime_sync_for_authority(
        &db_pool,
        &database_runtime_config,
        &runtime_authority_state,
        clients.as_ref(),
    )
    .await?;

    let userinfo_endpoint = userinfo_endpoint_for_oidc_runtime(
        oidc_runtime.as_deref(),
        token_runtime.validator.as_ref(),
        &db_pool,
        &issuer,
    );

    let dcr_runtime = dcr_runtime_for_authority(
        &db_pool,
        cfg.as_ref(),
        database_runtime_policy,
        &database_runtime_config,
    )
    .await?;

    let upstream_runtime = upstream_runtime_for_authority(
        cfg.as_ref(),
        database_runtime_policy,
        &runtime_state_namespace,
    )?;
    let browser_auth_runtime =
        browser_auth_runtime_for_authority(database_runtime_policy, &runtime_state_namespace)?;
    let device_runtime =
        device_runtime_stores_from_shared_env(cfg.as_ref(), &runtime_state_namespace)?;
    let federation_runtime = federation_runtime_for_authority(&db_pool, database_runtime_policy)?;

    let management =
        ManagementState::try_from_env_with_database(&db_pool, &runtime_state_namespace).await?;

    let state = app_state_from_parts(AppStateParts {
        cfg,
        base_url,
        issuer,
        environment_id: database_runtime_config.environment_id,
        runtime_authority: runtime_authority_state,
        runtime_restart: RuntimeRestartState::new(),
        clients,
        token: token_runtime,
        transport: transport_security,
        dpop: dpop_middleware,
        protocol: protocol_runtime,
        oidc: oidc_runtime,
        oidc_sessions,
        userinfo_endpoint,
        db_pool,
        registry,
        upstream: upstream_runtime,
        browser_auth: browser_auth_runtime,
        dcr: dcr_runtime,
        runtime_sync: runtime_sync.clone(),
        management,
        federation: federation_runtime,
        key_manager,
        jwt_introspection_key_manager,
        device: device_runtime,
    });

    Ok(BuiltServerRuntime {
        state,
        database_runtime_config,
        runtime_sync,
    })
}

async fn spawn_server_background_tasks(runtime: &BuiltServerRuntime) -> Result<()> {
    let cleanup_interval_secs = u64::from(
        runtime
            .database_runtime_config
            .state
            .policy
            .cleanup_interval_seconds,
    );
    spawn_cleanup_task(&runtime.state, cleanup_interval_secs);
    spawn_runtime_config_monitor_task(
        &runtime.state,
        &runtime.database_runtime_config,
        runtime.runtime_sync.config_monitor_interval_secs,
    )?;
    spawn_runtime_authority_notification_listener_task(
        &runtime.state,
        &runtime.database_runtime_config,
    )
    .await?;
    Ok(())
}

async fn serve(args: &Args, state: ServerAppState) -> Result<()> {
    let runtime_restart = state.runtime_restart.clone();
    let app = build_router(state);
    let addr: std::net::SocketAddr = format!("{}:{}", args.host, args.port).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        runtime_restart.notified().await;
    })
    .await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    aegaeon_server::install_rustls_crypto_provider();
    init_tracing();
    let args = Args::parse();
    log_startup(&args);
    let runtime = build_server_runtime(&args).await?;
    spawn_server_background_tasks(&runtime).await?;
    let runtime_restart = runtime.state.runtime_restart.clone();
    serve(&args, runtime.state).await?;
    if let Some(request) = runtime_restart.request() {
        tracing::error!(
            target: "runtime_restart",
            request_id = request.request_id(),
            issuer_host = request.issuer_host(),
            reason = ?request.reason(),
            "runtime restart requested; terminating process after graceful shutdown"
        );
        terminate_runtime();
    }
    if runtime_restart.is_requested() {
        tracing::error!(
            target: "runtime_restart",
            "runtime restart requested without readable metadata; terminating process after graceful shutdown"
        );
        terminate_runtime();
    }
    Ok(())
}

#[cfg(test)]
#[path = "main/tests.rs"]
mod tests;

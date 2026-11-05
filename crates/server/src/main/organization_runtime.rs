//! Production startup and one-shot work on the operator-selected database generation.
use super::{build_server_runtime_with_inputs, startup_runtime_issuer_host, BuiltServerRuntime};
use crate::config::{BootstrapConfig, ServerConfig};
#[cfg(test)]
use crate::organizations::witness::deployment::configuration::Configuration;
use crate::organizations::{
    invitations::transport::trust::Trust, request_work::CapacityClass,
    witness::deployment::dispatch::EnvironmentDispatcher,
};
use crate::runtime_configuration::DatabaseRuntimeConfiguration;
use crate::web::{OrganizationDeliveryRequest, OrganizationDeliveryResult};
use anyhow::{ensure, Result};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{path::PathBuf, time::Duration};
use uuid::Uuid;

#[path = "organization_runtime/serving.rs"]
mod serving;
pub(super) use serving::serve;

pub(super) struct Startup {
    pub pool: PgPool,
    management_pool: Option<PgPool>,
    environment: Uuid,
    issuer: String,
    #[cfg(test)]
    token: Option<String>,
    generation: Option<crate::organizations::lifecycle::Selection>,
}

impl Startup {
    pub(super) async fn management_database(
        &self,
        config: &crate::config::DatabaseConfig,
    ) -> Result<Option<PgPool>> {
        if self.generation.is_some() {
            return Ok(self.management_pool.clone());
        }
        match config.management_from_env()? {
            Some(config) => Ok(Some(crate::db::connect_required_pool(&config).await?)),
            None => Ok(None),
        }
    }

    pub(super) fn namespace(&self) -> Result<crate::config::RuntimeStateNamespace> {
        match self.generation {
            Some(selected) => Ok(selected.namespace(self.environment)?),
            None => Ok(crate::config::RuntimeStateNamespace::from_environment_id(
                self.environment,
            )),
        }
    }

    pub(super) fn check(
        &self,
        config: &ServerConfig,
        loaded: &DatabaseRuntimeConfiguration,
    ) -> Result<()> {
        ensure!(
            loaded.environment_id == self.environment && loaded.issuer_url == self.issuer,
            "Organizations startup namespace differs from independent selection"
        );
        #[cfg(test)]
        if let Some(token) = &self.token {
            config.validate_organization_store_domain(loaded.state.policy.oidc_enabled, token)?;
        }
        #[cfg(not(test))]
        let _ = config;
        Ok(())
    }
}

struct Prepared {
    issuer_host: String,
    bootstrap: BootstrapConfig,
    startup: Startup,
    dispatcher: EnvironmentDispatcher,
    delivery_trust: Trust,
}

impl Prepared {
    async fn from_environment() -> Result<Self> {
        let path = std::env::var_os("AEGAEON_ORGANIZATION_RUNTIME_CONFIG")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .ok_or_else(|| {
                anyhow::anyhow!("independent Organizations runtime configuration is required")
            })?;
        let config = crate::organizations::lifecycle::configuration::Configuration::load(&path)?;
        let issuer_host = startup_runtime_issuer_host()?;
        let bootstrap = BootstrapConfig::try_from_env()?;
        let (environment, issuer) =
            config.startup_environment(&issuer_host, bootstrap.database().url())?;
        let delivery_trust = config.delivery_trust()?;
        let generation = config.selection();
        let management = bootstrap.database().management_from_env()?;
        let runtime = config
            .connect(
                PgPoolOptions::new()
                    .max_connections(bootstrap.database().max_connections)
                    .min_connections(0)
                    .acquire_timeout(Duration::from_secs(
                        bootstrap.database().acquire_timeout_secs,
                    )),
                management.as_ref().map(crate::config::DatabaseConfig::url),
            )
            .await?;
        let pool = runtime.pool().clone();
        let management_pool = runtime.management_pool().cloned();
        let dispatcher =
            crate::organizations::witness::deployment::dispatch::Dispatcher::current(runtime)
                .environment(environment, &issuer)?;
        Ok(Self {
            issuer_host,
            bootstrap,
            startup: Startup {
                pool,
                management_pool,
                environment,
                issuer,
                generation: Some(generation),
                #[cfg(test)]
                token: None,
            },
            dispatcher,
            delivery_trust,
        })
    }

    #[cfg(test)]
    fn new(
        config: Configuration,
        issuer_host: String,
        bootstrap: BootstrapConfig,
        token: String,
    ) -> Result<Self> {
        let (environment, issuer) = config.startup_environment(&issuer_host)?;
        config.check_runtime(environment, &issuer, bootstrap.database().url(), &token)?;
        let delivery_trust = config.delivery_trust()?;
        let deployment = config.dispatcher()?;
        let dispatcher = deployment.environment(environment, &issuer)?;
        // Freeze the same verified TLS options and CA bytes used by the observer.
        // No eager connection or pool-maintenance replacement precedes ownership.
        let pool = PgPoolOptions::new()
            .max_connections(bootstrap.database().max_connections)
            .min_connections(0)
            .acquire_timeout(Duration::from_secs(
                bootstrap.database().acquire_timeout_secs,
            ))
            .connect_lazy_with(deployment.primary_options());
        Ok(Self {
            issuer_host,
            bootstrap,
            startup: Startup {
                pool,
                management_pool: None,
                environment,
                issuer,
                token: Some(token),
                generation: None,
            },
            dispatcher,
            delivery_trust,
        })
    }

    async fn build(self) -> Result<(BuiltServerRuntime, EnvironmentDispatcher)> {
        let Self {
            issuer_host,
            bootstrap,
            startup,
            dispatcher,
            ..
        } = self;
        let pool = startup.pool.clone();
        let result = match dispatcher.startup_preflight(move || async move {
            build_server_runtime_with_inputs(issuer_host, bootstrap, Some(startup)).await
        }) {
            Ok(execution) => execution.result().await,
            Err(error) => Err(error),
        };
        // Failed startup also closes every registered credential pool. No
        // management session lock may outlive the failed serving runtime.
        if !matches!(&result, Ok(Ok(_))) {
            let _ = tokio::time::timeout(Duration::from_secs(10), dispatcher.deployment().close())
                .await;
        }
        let runtime = startup_outcome(&pool, result).await?;
        Ok((runtime, dispatcher))
    }
}

async fn startup_outcome<T>(
    pool: &PgPool,
    result: std::result::Result<Result<T>, crate::organizations::witness::Error>,
) -> Result<T> {
    let reason_code = match result {
        Ok(Ok(runtime)) => return Ok(runtime),
        Ok(Err(_)) => "runtime_build_failed",
        Err(error) => error.reason_code(),
    };
    // Source errors can contain credentials or private store observations. Only
    // the fixed classifier crosses this operator-log boundary.
    tracing::error!(
        target: "organization_startup",
        stage = "owned_startup",
        reason_code,
        "Organizations startup refused"
    );
    if tokio::time::timeout(Duration::from_secs(10), pool.close())
        .await
        .is_err()
    {
        tracing::error!(
            target: "organization_startup",
            stage = "pool_cleanup",
            reason_code = "pool_cleanup_deadline",
            "Organizations startup cleanup incomplete"
        );
    }
    anyhow::bail!("Organizations owned startup failed")
}

/// Deliver once using independently selected, observed startup and work scopes.
/// No background monitor or implicit retry is started by this one-shot entry.
///
/// # Errors
/// Refuses missing configuration, namespace/store mismatch, fenced authority,
/// unavailable transport, incomplete cleanup or unsuccessful delivery processing.
pub async fn deliver_organization_invitation(
    input: OrganizationDeliveryRequest,
) -> Result<OrganizationDeliveryResult> {
    crate::install_rustls_crypto_provider();
    let prepared = Prepared::from_environment().await?;
    let trust = prepared.delivery_trust.clone();
    let (runtime, dispatcher) = prepared.build().await?;
    let pool = runtime.state.db_pool.clone();
    let result = dispatcher.start(CapacityClass::Ordinary, move || async move {
        runtime
            .state
            .deliver_organization_invitation_with_trust(input, &trust)
            .await
    });
    let result = match result {
        Ok(execution) => execution
            .result()
            .await
            .map_err(anyhow::Error::from)
            .and_then(|value| value),
        Err(error) => Err(error.into()),
    };
    tokio::time::timeout(Duration::from_secs(10), pool.close())
        .await
        .map_err(|_| anyhow::anyhow!("Organizations delivery pool cleanup incomplete"))?;
    result.map_err(|_| anyhow::anyhow!("Organizations delivery unavailable"))
}

#[cfg(test)]
#[path = "organization_runtime/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "organization_runtime/tests/diagnostics.rs"]
mod diagnostics_tests;

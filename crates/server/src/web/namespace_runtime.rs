//! Private namespace capability, bound to the server-owned database and services.
use super::AppState;
use crate::authcode::{TokenIssuer, TokenValidator};
use crate::config::ServerConfig;
use crate::oidc::{OidcConfig, UserinfoEndpoint};
use crate::subject_ownership::history::preflight::verify_compiled_catalog;
use anyhow::{bail, Context, Result};
use axum::{http::StatusCode, response::Response};
use serde_json::Value;
use sqlx::{postgres::PgConnectOptions, Row};
use std::sync::Arc;
use uuid::Uuid;

pub(crate) struct NamespacePermit {
    environment: Uuid,
    issuer: Arc<String>,
    options_generation: Arc<PgConnectOptions>,
    configuration: Arc<ServerConfig>,
    token_issuer: Arc<TokenIssuer>,
    token_validator: Arc<TokenValidator>,
    token_store: Arc<crate::authcode::store::TokenStore>,
    oidc: Option<Arc<OidcConfig>>,
    userinfo: Option<Arc<UserinfoEndpoint>>,
    application: Option<Arc<crate::application_authorization::Authority>>,
    membership_generation: Option<Arc<PgConnectOptions>>,
    _receipt_id: Uuid,
}

/// A checked borrow cannot be manufactured or attached to another runtime.
pub(crate) struct NamespaceCapability<'a> {
    _permit: &'a NamespacePermit,
    state: &'a AppState,
}

impl NamespaceCapability<'_> {
    pub(crate) fn state(&self) -> &AppState {
        self.state
    }
}

fn same_optional<T>(left: Option<&Arc<T>>, right: Option<&Arc<T>>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => Arc::ptr_eq(left, right),
        (None, None) => true,
        _ => false,
    }
}

impl NamespacePermit {
    fn matches(&self, state: &AppState) -> bool {
        !state.runtime_restart.is_requested()
            && self.environment == state.environment_id
            && Arc::ptr_eq(&self.issuer, &state.issuer)
            && state.base_url.as_str() == self.issuer.as_str()
            && Arc::ptr_eq(&self.options_generation, &state.db_pool.connect_options())
            && Arc::ptr_eq(&self.configuration, &state.cfg)
            && Arc::ptr_eq(&self.token_issuer, &state.tokens.issuer)
            && Arc::ptr_eq(&self.token_validator, &state.tokens.validator)
            && Arc::ptr_eq(&self.token_store, &state.tokens.store)
            && same_optional(
                self.application.as_ref(),
                state.application_authority.as_ref(),
            )
            && state
                .application_authority
                .as_ref()
                .is_none_or(|authority| {
                    Arc::ptr_eq(
                        &self.options_generation,
                        &authority.projections.connect_options(),
                    ) && same_optional(
                        self.membership_generation.as_ref(),
                        authority
                            .memberships
                            .as_ref()
                            .map(sqlx::PgPool::connect_options)
                            .as_ref(),
                    )
                })
            && same_optional(self.oidc.as_ref(), state.oidc.config.as_ref())
            && same_optional(
                self.userinfo.as_ref(),
                state.oidc.userinfo_endpoint.as_ref(),
            )
    }
}

impl AppState {
    /// Construct validated opaque state from the documented runtime configuration.
    ///
    /// # Errors
    /// Refuses incompatible database authority, pending history, or issuer mismatch.
    pub async fn from_environment() -> Result<Self> {
        crate::server_runtime::from_environment().await
    }

    /// Wait for mandatory runtime monitoring to request drain/restart.
    /// Embedders must stop accepting requests and drain their listener when this resolves.
    pub async fn shutdown_requested(&self) {
        self.runtime_restart.notified().await;
    }

    pub(crate) fn require_subject_namespace(&self) -> Result<NamespaceCapability<'_>, Response> {
        self.require_subject_namespace_for(self.environment_id)
    }

    pub(crate) fn require_subject_namespace_for(
        &self,
        environment: Uuid,
    ) -> Result<NamespaceCapability<'_>, Response> {
        match self.subject_namespace.as_deref() {
            Some(permit) if environment == self.environment_id && permit.matches(self) => {
                Ok(NamespaceCapability {
                    _permit: permit,
                    state: self,
                })
            }
            _ => Err(super::no_cache_json_error_with_iss(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                Some("Subject namespace unavailable"),
                self.issuer.as_str(),
            )),
        }
    }

    pub(crate) async fn validate_subject_namespace(&mut self) -> Result<()> {
        self.subject_namespace = None;
        let oidc_issuer = self.oidc.config.as_ref().map(|c| c.issuer.as_str());
        if self.base_url.as_str() != self.issuer.as_str()
            || oidc_issuer.is_some_and(|issuer| issuer != self.issuer.as_str())
            || !self
                .tokens
                .issuer
                .has_server_issuer(&self.issuer, oidc_issuer)
            || !self.tokens.validator.has_server_issuer(&self.issuer)
        {
            bail!("server identity service issuer mismatch");
        }
        let options_generation = self.db_pool.connect_options();
        if self
            .application_authority
            .as_ref()
            .is_some_and(|authority| {
                !Arc::ptr_eq(
                    &options_generation,
                    &authority.projections.connect_options(),
                )
            })
        {
            bail!("application projection authority is not the server-owned database");
        }
        let receipt_id =
            validate_database_inputs(&self.db_pool, self.environment_id, self.issuer.as_str())
                .await?;
        if !Arc::ptr_eq(&options_generation, &self.db_pool.connect_options()) {
            bail!("server database connection generation changed during validation");
        }
        // Rebuild the server adapter from these exact inputs; a prebuilt endpoint
        // cannot serve as evidence that its private source uses this database.
        self.oidc.userinfo_endpoint = self
            .oidc
            .config
            .as_ref()
            .filter(|config| config.userinfo_enabled)
            .map(|_| {
                Arc::new(UserinfoEndpoint::new(
                    self.tokens.validator.as_ref().clone(),
                    self.db_pool.clone(),
                    self.issuer.as_str().to_owned(),
                ))
            });
        self.subject_namespace = Some(Arc::new(NamespacePermit {
            environment: self.environment_id,
            issuer: Arc::clone(&self.issuer),
            options_generation,
            configuration: Arc::clone(&self.cfg),
            token_issuer: Arc::clone(&self.tokens.issuer),
            token_validator: Arc::clone(&self.tokens.validator),
            token_store: Arc::clone(&self.tokens.store),
            oidc: self.oidc.config.clone(),
            userinfo: self.oidc.userinfo_endpoint.clone(),
            application: self.application_authority.clone(),
            membership_generation: self.application_authority.as_ref().and_then(|authority| {
                authority
                    .memberships
                    .as_ref()
                    .map(sqlx::PgPool::connect_options)
            }),
            _receipt_id: receipt_id,
        }));
        Ok(())
    }
}

pub(crate) async fn validate_database_inputs(
    pool: &sqlx::PgPool,
    environment: Uuid,
    issuer: &str,
) -> Result<Uuid> {
    let mut tx = pool.begin().await?;
    let rows = sqlx::query(
        "SELECT record_type,row_key,payload FROM aegaeon.validate_subject_ownership_namespace_v1($1)",
    )
    .bind(environment)
    .fetch_all(&mut *tx)
    .await
    .context("subject namespace database validation refused")?;
    let mut namespace = None;
    let mut catalog = Vec::new();
    for row in rows {
        let kind: String = row.try_get("record_type")?;
        let key: String = row.try_get("row_key")?;
        let text: String = row.try_get("payload")?;
        let value: Value = serde_json::from_str(&text)?;
        match kind.as_str() {
            "namespace" if namespace.is_none() => namespace = Some(value),
            "catalog" => catalog.push((key, value)),
            _ => bail!("unexpected namespace validation record"),
        }
    }
    let namespace = namespace.context("namespace receipt missing")?;
    if namespace["environment_id"].as_str() != Some(environment.to_string().as_str())
        || namespace["issuer_url"].as_str() != Some(issuer)
        || namespace["contract_version"].as_u64() != Some(1)
        || namespace["kind"] != namespace["origin"]
        || !matches!(namespace["kind"].as_str(), Some("legacy" | "fresh"))
    {
        bail!("namespace does not match server database and issuer");
    }
    verify_compiled_catalog(
        &catalog,
        namespace["schema_sha256"]
            .as_str()
            .context("namespace schema identity missing")?,
        namespace["session_actor"]
            .as_str()
            .context("runtime login identity missing")?,
    )?;
    let receipt = Uuid::parse_str(
        namespace["receipt_id"]
            .as_str()
            .context("receipt missing")?,
    )?;
    tx.rollback().await?;
    Ok(receipt)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod lifecycle_tests;

#[cfg(test)]
mod acceptance_tests;

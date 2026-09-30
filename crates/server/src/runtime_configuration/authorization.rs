//! Coherent client and profile selection tied to the loaded runtime configuration.
use std::sync::Arc;

use serde_json::Value;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::client_registry::ClientRegistry;
use crate::config::ServerConfig;
use crate::oauth_profile::ResolvedProfile;
use crate::oidc::OidcConfig;
use crate::runtime_clients::load_authorization_client_in_tx;

use super::{DatabaseRuntimeConfiguration, RuntimeAuthorityRevision, RuntimeConfigurationError};

/// Only the actual loader constructs this original source, before public copies
/// of the database configuration can be changed by another caller.
#[derive(Clone)]
pub(super) struct AuthorizationSource {
    pub(super) environment_id: Uuid,
    pub(super) issuer_host: String,
    pub(super) issuer_url: String,
    pub(super) document: Value,
    pub(super) revision: RuntimeAuthorityRevision,
    pub(super) state: super::RuntimeConfigurationState,
    pub(super) keys: crate::runtime_keys::RuntimeKeySet,
    pub(super) stable_facts: Value,
}

impl std::fmt::Debug for AuthorizationSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizationSource")
            .finish_non_exhaustive()
    }
}

/// Actual startup derivation, retaining the exact source and consumed instances.
/// No public constructor accepts independently assembled facts.
#[derive(Clone)]
pub struct AuthorizationRuntime {
    source: Arc<AuthorizationSource>,
    configuration: Arc<ServerConfig>,
    oidc: Option<Arc<OidcConfig>>,
}

impl DatabaseRuntimeConfiguration {
    /// Derive the instances subsequently used by authorization from the original
    /// loader source. Run once at startup, after the read transaction ends.
    ///
    /// # Errors
    /// Returns an error for an invalid policy or unavailable OIDC key material.
    pub async fn derive_authorization_runtime(
        &self,
        baseline: ServerConfig,
    ) -> anyhow::Result<AuthorizationRuntime> {
        let source = self.authorization_source.clone();
        let configuration = Arc::new(baseline.with_management_policy(&source.state.policy)?);
        let oidc = OidcConfig::from_management_snapshot_async(
            &source.issuer_url,
            &source.state.policy,
            &source.keys,
        )
        .await?
        .map(Arc::new);
        Ok(AuthorizationRuntime {
            source,
            configuration,
            oidc,
        })
    }
}

impl AuthorizationRuntime {
    #[must_use]
    pub fn configuration(&self) -> Arc<ServerConfig> {
        self.configuration.clone()
    }

    #[must_use]
    pub fn oidc(&self) -> Option<Arc<OidcConfig>> {
        self.oidc.clone()
    }

    pub(crate) fn issuer_host(&self) -> Arc<String> {
        Arc::new(self.source.issuer_host.clone())
    }

    pub(crate) fn revision(&self) -> RuntimeAuthorityRevision {
        self.source.revision.clone()
    }

    pub(crate) fn uses_instances(
        &self,
        configuration: &Arc<ServerConfig>,
        oidc: Option<&Arc<OidcConfig>>,
    ) -> bool {
        Arc::ptr_eq(&self.configuration, configuration)
            && match (&self.oidc, oidc) {
                (None, None) => true,
                (Some(expected), Some(actual)) => Arc::ptr_eq(expected, actual),
                _ => false,
            }
    }

    pub(crate) async fn observe(
        &self,
        pool: &PgPool,
        environment: Uuid,
        issuer: &str,
        client_id: &str,
        clients: &ClientRegistry,
        #[cfg(test)] barriers: Option<&crate::runtime_authority::AuthorizationReadBarriers>,
    ) -> Result<AuthorizationObservation, RuntimeConfigurationError> {
        let source = &self.source;
        let mut tx = super::begin_runtime_configuration_snapshot(pool).await?;
        let rows = sqlx::query(super::ACTIVE_RUNTIME_CONFIGURATION_FOR_ISSUER_HOST)
            .bind(&source.issuer_host)
            .fetch_all(&mut *tx)
            .await
            .map_err(RuntimeConfigurationError::DatabaseQuery)?;
        let [row] = rows.as_slice() else {
            return Err(if rows.is_empty() {
                RuntimeConfigurationError::NotFound(source.issuer_host.clone())
            } else {
                RuntimeConfigurationError::AmbiguousIssuerHost(source.issuer_host.clone())
            });
        };
        let observed_environment: Uuid = row
            .try_get("environment_id")
            .map_err(RuntimeConfigurationError::DatabaseQuery)?;
        let observed_issuer: String = row
            .try_get("issuer_url")
            .map_err(RuntimeConfigurationError::DatabaseQuery)?;
        let document: Value = row
            .try_get("configuration_document")
            .map_err(RuntimeConfigurationError::DatabaseQuery)?;
        if environment != source.environment_id
            || observed_environment != environment
            || issuer != source.issuer_url
            || observed_issuer != issuer
            || document != source.document
        {
            return Err(RuntimeConfigurationError::ConcurrentModification(
                source.issuer_host.clone(),
            ));
        }
        #[cfg(test)]
        if let Some(barriers) = barriers {
            barriers.observed.wait().await;
            barriers.resume.wait().await;
        }
        let revision = super::load_active_runtime_configuration_revision_for_issuer_host_in_tx(
            &mut tx,
            &source.issuer_host,
        )
        .await?;
        let stable_facts = load_stable_facts(&mut tx, &source.issuer_host).await?;
        if stable_facts != source.stable_facts
            || !revision.stable_authority_matches(&source.revision)
        {
            return Err(RuntimeConfigurationError::ConcurrentModification(
                source.issuer_host.clone(),
            ));
        }
        let client =
            load_authorization_client_in_tx(&mut tx, &source.issuer_host, client_id).await?;
        let profile = crate::oauth_profile::observe_downstream_profile_in_tx(
            &mut tx,
            &source.issuer_host,
            client_id,
        )
        .await
        .map_err(RuntimeConfigurationError::DatabaseQuery)?;
        if client.as_ref().is_some_and(|c| {
            c.environment_id != environment
                || c.configuration_id != revision.active_configuration_version_id()
        }) || profile.as_ref().is_some_and(|p| {
            p.environment_id != environment
                || p.configuration_id != revision.active_configuration_version_id()
                || client
                    .as_ref()
                    .is_none_or(|c| c.requested_profile_id != p.requested_profile_id)
        }) {
            return Err(RuntimeConfigurationError::ConcurrentModification(
                source.issuer_host.clone(),
            ));
        }
        tx.commit()
            .await
            .map_err(RuntimeConfigurationError::DatabaseQuery)?;
        // The RR transaction ends before remote JWKS or PAR/Redis execution.
        let selected_clients = Arc::new(
            clients.for_authorization_observation(client.as_ref().map(|c| c.client.clone())),
        );
        Ok(AuthorizationObservation {
            profile: profile.map(|profile| profile.effective),
            selected_clients,
        })
    }
}

pub(crate) struct AuthorizationObservation {
    pub(crate) profile: Option<ResolvedProfile>,
    pub(crate) selected_clients: Arc<ClientRegistry>,
}

/// Exact source correspondence supplements the legacy fingerprint guard. This
/// value stays private: it contains encrypted key handles and token hashes.
/// Both this read and the typed key loader run in the same startup RR snapshot;
/// the request compares the full values in its own RR snapshot. Timestamps are
/// numeric microseconds, preserving precision independently of session timezone.
pub(super) async fn load_stable_facts(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    issuer_host: &str,
) -> Result<Value, RuntimeConfigurationError> {
    sqlx::query_scalar(
        r"
SELECT jsonb_build_object(
  'keys', COALESCE((
    SELECT jsonb_agg(jsonb_build_object(
      'id', rk.id, 'environment_id', rk.environment_id,
      'configuration_version_id', rk.configuration_version_id,
      'usage', rk.usage, 'kid', rk.kid, 'algorithm', rk.algorithm,
      'provider', rk.provider, 'status', rk.status,
      'retiring_expires_at_micros', (extract(epoch FROM rk.retiring_expires_at)*1000000)::bigint,
      'public_jwk', rk.public_jwk, 'key_handle', rk.key_handle,
      'provider_configuration', rk.provider_configuration
    ) ORDER BY rk.usage, rk.status, rk.created_at, rk.id)
    FROM aegaeon.runtime_keys rk
    WHERE rk.environment_id=rt.environment_id
      AND (rk.status='ACTIVE' OR (rk.status='RETIRING' AND rk.retiring_expires_at>now()))
  ), '[]'::jsonb),
  'dcr_bearer', (
    SELECT jsonb_build_object('token_hash', bearer.token_hash,
      'token_hash_algorithm', bearer.token_hash_algorithm)
    FROM aegaeon.environment_dcr_bearer_tokens bearer
    WHERE bearer.environment_id=rt.environment_id AND bearer.token_hash_algorithm='sha256'
  )
)
FROM aegaeon.active_runtime_environments rt WHERE rt.issuer_host=$1
",
    )
    .bind(issuer_host)
    .fetch_one(&mut **tx)
    .await
    .map_err(RuntimeConfigurationError::DatabaseQuery)
}

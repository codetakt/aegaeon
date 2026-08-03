mod document;
mod revision;

pub(crate) use self::document::{
    parse_configuration_document_v1, parse_federation_document_value,
    serialize_canonical_configuration_document_v1, ConfigurationDocumentV1,
};
pub use self::document::{
    parse_runtime_configuration_document, RuntimeConfigurationState, RuntimeKeyStoreConfiguration,
};
pub use self::revision::{RuntimeAuthorityRevision, RuntimeFingerprintError};

use serde_json::Value;
use sqlx::{PgPool, Postgres, Row, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::runtime_clients::{
    load_active_runtime_client_fingerprint_for_issuer_host_in_tx, RuntimeClientSnapshotError,
};
use crate::runtime_keys::{
    load_runtime_key_set_for_issuer_host_in_tx, RuntimeKeySet, RuntimeKeySetError,
};

const ACTIVE_RUNTIME_CONFIGURATION_FOR_ISSUER_HOST: &str = r"
SELECT
  rt.environment_id,
  rt.issuer_host,
  rt.issuer_url,
  rt.configuration_version_id AS active_configuration_version_id,
  rt.configuration_document
FROM aegaeon.active_runtime_environments rt
WHERE rt.issuer_host = $1
ORDER BY rt.environment_id
LIMIT 2
";

#[derive(Clone, Debug)]
pub struct DatabaseRuntimeConfiguration {
    pub environment_id: Uuid,
    pub issuer_host: String,
    pub issuer_url: String,
    pub active_configuration_version_id: Uuid,
    pub active_configuration_document_fingerprint: String,
    pub active_runtime_key_set_fingerprint: String,
    pub active_runtime_client_fingerprint: String,
    pub active_dcr_bearer_token_fingerprint: String,
    pub state: RuntimeConfigurationState,
    pub runtime_keys: RuntimeKeySet,
}

impl DatabaseRuntimeConfiguration {
    /// Rebuild the typed authority revision from the validated database snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeFingerprintError`] if a caller constructed this public snapshot with
    /// non-canonical runtime fingerprints instead of using the database loader.
    pub fn authority_revision(&self) -> Result<RuntimeAuthorityRevision, RuntimeFingerprintError> {
        RuntimeAuthorityRevision::try_new(
            self.active_configuration_version_id,
            self.active_configuration_document_fingerprint.clone(),
            self.active_runtime_key_set_fingerprint.clone(),
            self.active_runtime_client_fingerprint.clone(),
            self.active_dcr_bearer_token_fingerprint.clone(),
        )
    }
}

#[derive(Debug, Error)]
pub enum RuntimeConfigurationError {
    #[error("runtime issuer host selector is not a valid issuer host")]
    InvalidIssuerHostSelector,

    #[error("issuer host for database runtime configuration must not be empty")]
    EmptyIssuerHost,

    #[error("no ACTIVE management environment/configuration version matched issuer host `{0}`")]
    NotFound(String),

    #[error("multiple ACTIVE management environments matched issuer host `{0}`")]
    AmbiguousIssuerHost(String),

    #[error("failed to query database runtime configuration: {0}")]
    DatabaseQuery(sqlx::Error),

    #[error("failed to decode database runtime configuration column `{0}`")]
    RowDecode(&'static str),

    #[error("invalid active runtime configuration document: {0}")]
    InvalidDocument(&'static str),

    #[error("invalid active runtime configuration document shape: {0}")]
    InvalidDocumentShape(serde_json::Error),

    #[error("invalid active runtime key set: {0}")]
    RuntimeKeys(#[from] RuntimeKeySetError),

    #[error("invalid active runtime client projection: {0}")]
    RuntimeClients(#[from] RuntimeClientSnapshotError),

    #[error("invalid active runtime authority fingerprint: {0}")]
    InvalidRuntimeFingerprint(#[from] RuntimeFingerprintError),

    #[error("database runtime configuration changed while loading issuer host `{0}`")]
    ConcurrentModification(String),
}

pub async fn load_database_runtime_configuration(
    pool: &PgPool,
    issuer_host_selector: &str,
) -> Result<DatabaseRuntimeConfiguration, RuntimeConfigurationError> {
    let issuer_host = normalize_runtime_issuer_host_selector(issuer_host_selector)
        .ok_or(RuntimeConfigurationError::InvalidIssuerHostSelector)?;
    let mut tx = begin_runtime_configuration_snapshot(pool).await?;
    let rows = sqlx::query(ACTIVE_RUNTIME_CONFIGURATION_FOR_ISSUER_HOST)
        .bind(&issuer_host)
        .fetch_all(&mut *tx)
        .await
        .map_err(RuntimeConfigurationError::DatabaseQuery)?;

    let [row] = rows.as_slice() else {
        return if rows.is_empty() {
            Err(RuntimeConfigurationError::NotFound(issuer_host))
        } else {
            Err(RuntimeConfigurationError::AmbiguousIssuerHost(issuer_host))
        };
    };

    let environment_id: Uuid = row
        .try_get("environment_id")
        .map_err(|_| RuntimeConfigurationError::RowDecode("environment_id"))?;
    let issuer_host: String = row
        .try_get("issuer_host")
        .map_err(|_| RuntimeConfigurationError::RowDecode("issuer_host"))?;
    let issuer_url: String = row
        .try_get("issuer_url")
        .map_err(|_| RuntimeConfigurationError::RowDecode("issuer_url"))?;
    let active_configuration_version_id: Uuid = row
        .try_get("active_configuration_version_id")
        .map_err(|_| RuntimeConfigurationError::RowDecode("active_configuration_version_id"))?;
    let configuration_document: Value = row
        .try_get("configuration_document")
        .map_err(|_| RuntimeConfigurationError::RowDecode("configuration_document"))?;
    let state =
        parse_runtime_configuration_document(&configuration_document, &issuer_host, &issuer_url)?;
    let revision =
        load_active_runtime_configuration_revision_for_issuer_host_in_tx(&mut tx, &issuer_host)
            .await?;
    if revision.active_configuration_version_id() != active_configuration_version_id {
        return Err(RuntimeConfigurationError::ConcurrentModification(
            issuer_host,
        ));
    }
    let runtime_keys = load_runtime_key_set_for_issuer_host_in_tx(&mut tx, &issuer_host).await?;
    runtime_keys.validate_allowed_signing_algorithms(&state.policy.allowed_signing_algorithms)?;
    tx.commit()
        .await
        .map_err(RuntimeConfigurationError::DatabaseQuery)?;

    Ok(DatabaseRuntimeConfiguration {
        environment_id,
        issuer_host,
        issuer_url,
        active_configuration_version_id,
        active_configuration_document_fingerprint: revision
            .active_configuration_document_fingerprint()
            .to_string(),
        active_runtime_key_set_fingerprint: revision
            .active_runtime_key_set_fingerprint()
            .to_string(),
        active_runtime_client_fingerprint: revision.active_runtime_client_fingerprint().to_string(),
        active_dcr_bearer_token_fingerprint: revision
            .active_dcr_bearer_token_fingerprint()
            .to_string(),
        state,
        runtime_keys,
    })
}

async fn begin_runtime_configuration_snapshot(
    pool: &PgPool,
) -> Result<Transaction<'_, Postgres>, RuntimeConfigurationError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(RuntimeConfigurationError::DatabaseQuery)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(RuntimeConfigurationError::DatabaseQuery)?;
    Ok(tx)
}

pub async fn load_active_runtime_configuration_revision_for_issuer_host(
    pool: &PgPool,
    issuer_host: &str,
) -> Result<RuntimeAuthorityRevision, RuntimeConfigurationError> {
    let issuer_host = issuer_host.trim();
    if issuer_host.is_empty() {
        return Err(RuntimeConfigurationError::EmptyIssuerHost);
    }

    let mut tx = begin_runtime_configuration_snapshot(pool).await?;
    let revision =
        load_active_runtime_configuration_revision_for_issuer_host_in_tx(&mut tx, issuer_host)
            .await?;
    tx.commit()
        .await
        .map_err(RuntimeConfigurationError::DatabaseQuery)?;
    Ok(revision)
}

async fn load_active_runtime_configuration_revision_for_issuer_host_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    issuer_host: &str,
) -> Result<RuntimeAuthorityRevision, RuntimeConfigurationError> {
    let issuer_host = issuer_host.trim();
    if issuer_host.is_empty() {
        return Err(RuntimeConfigurationError::EmptyIssuerHost);
    }

    let rows = sqlx::query(
        crate::runtime_authority_queries::ACTIVE_RUNTIME_AUTHORITY_REVISION_FOR_ISSUER_HOST,
    )
    .bind(issuer_host)
    .fetch_all(&mut **tx)
    .await
    .map_err(RuntimeConfigurationError::DatabaseQuery)?;

    let [row] = rows.as_slice() else {
        return if rows.is_empty() {
            Err(RuntimeConfigurationError::NotFound(issuer_host.to_string()))
        } else {
            Err(RuntimeConfigurationError::AmbiguousIssuerHost(
                issuer_host.to_string(),
            ))
        };
    };

    let active_configuration_version_id = row
        .try_get("active_configuration_version_id")
        .map_err(|_| RuntimeConfigurationError::RowDecode("active_configuration_version_id"))?;
    let active_configuration_document_fingerprint = row
        .try_get("active_configuration_document_fingerprint")
        .map_err(|_| {
            RuntimeConfigurationError::RowDecode("active_configuration_document_fingerprint")
        })?;
    let active_runtime_key_set_fingerprint = row
        .try_get("active_runtime_key_set_fingerprint")
        .map_err(|_| RuntimeConfigurationError::RowDecode("active_runtime_key_set_fingerprint"))?;
    let active_dcr_bearer_token_fingerprint = row
        .try_get("active_dcr_bearer_token_fingerprint")
        .map_err(|_| RuntimeConfigurationError::RowDecode("active_dcr_bearer_token_fingerprint"))?;
    let active_runtime_client_fingerprint =
        load_active_runtime_client_fingerprint_for_issuer_host_in_tx(tx, issuer_host).await?;

    Ok(RuntimeAuthorityRevision::try_new(
        active_configuration_version_id,
        active_configuration_document_fingerprint,
        active_runtime_key_set_fingerprint,
        active_runtime_client_fingerprint,
        active_dcr_bearer_token_fingerprint,
    )?)
}

pub async fn load_active_runtime_configuration_version_id_for_issuer_host(
    pool: &PgPool,
    issuer_host: &str,
) -> Result<Uuid, RuntimeConfigurationError> {
    load_active_runtime_configuration_revision_for_issuer_host(pool, issuer_host)
        .await
        .map(|revision| revision.active_configuration_version_id())
}

pub fn normalize_runtime_issuer_host_selector(issuer_host: &str) -> Option<String> {
    let trimmed = issuer_host.trim();
    if trimmed.is_empty()
        || trimmed.contains("://")
        || trimmed.contains('/')
        || trimmed.contains('?')
        || trimmed.contains('#')
    {
        return None;
    }

    let url = url::Url::parse(&format!("https://{trimmed}")).ok()?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return None;
    }
    crate::util::canonical_url_host_port(&url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_issuer_host_selector_normalizes_case_and_non_default_port() {
        assert_eq!(
            normalize_runtime_issuer_host_selector("Auth.Example.com:8443"),
            Some("auth.example.com:8443".to_string())
        );
        assert_eq!(
            normalize_runtime_issuer_host_selector("auth.example.com:443"),
            Some("auth.example.com".to_string())
        );
        assert_eq!(
            normalize_runtime_issuer_host_selector("LOCALHOST:80"),
            Some("localhost:80".to_string())
        );
        assert_eq!(
            normalize_runtime_issuer_host_selector("[::1]:8443"),
            Some("[::1]:8443".to_string())
        );
        assert_eq!(
            normalize_runtime_issuer_host_selector("[::1]:443"),
            Some("[::1]".to_string())
        );
    }

    #[test]
    fn runtime_issuer_host_selector_rejects_url_forms() {
        for value in [
            "",
            "   ",
            "https://auth.example.com",
            "auth.example.com/path",
            "auth.example.com?tenant=a",
            "auth.example.com#fragment",
            "user:pass@auth.example.com",
        ] {
            assert_eq!(normalize_runtime_issuer_host_selector(value), None);
        }
    }
}

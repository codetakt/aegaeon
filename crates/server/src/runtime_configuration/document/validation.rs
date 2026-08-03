use super::schema::{ConfigurationDocumentV1, KeyStoreDocument};
use super::state::RuntimeKeyStoreConfiguration;
use crate::management::types::PolicyDocument;
use crate::runtime_configuration::RuntimeConfigurationError;

pub(super) fn validate_runtime_configuration_document(
    document: &ConfigurationDocumentV1,
    issuer_host: &str,
    issuer_url: &str,
) -> Result<(), RuntimeConfigurationError> {
    if document.schema_version != 1 {
        return Err(RuntimeConfigurationError::InvalidDocument(
            "schemaVersion must be 1",
        ));
    }
    if document.issuer_host != issuer_host {
        return Err(RuntimeConfigurationError::InvalidDocument(
            "issuerHost does not match environment",
        ));
    }
    if document.issuer_url != issuer_url {
        return Err(RuntimeConfigurationError::InvalidDocument(
            "issuerUrl does not match environment",
        ));
    }
    Ok(())
}

pub(super) fn validate_runtime_federation_policy(
    policy: &PolicyDocument,
    _issuer_url: &str,
) -> Result<(), RuntimeConfigurationError> {
    crate::federation::normalize_federation_outbound_allowed_domains(
        &policy.federation_outbound_allowed_domains,
    )
    .map_err(|_| {
        RuntimeConfigurationError::InvalidDocument(
            "federationOutboundAllowedDomains entries must be unique plain DNS domains",
        )
    })?;
    crate::upstream::normalize_upstream_outbound_allowed_domains(
        &policy.upstream_outbound_allowed_domains,
    )
    .map_err(|_| {
        RuntimeConfigurationError::InvalidDocument(
            "upstreamOutboundAllowedDomains entries must be unique plain DNS domains",
        )
    })?;

    Ok(())
}

pub(super) fn parse_scope_allowlist(
    scope_allowlist: &[String],
) -> Result<Vec<String>, RuntimeConfigurationError> {
    scope_allowlist
        .iter()
        .map(|value| {
            let scope = value.trim();
            if !scope.is_empty() && crate::oauth_scope::is_scope_token(scope) {
                Ok(scope.to_string())
            } else {
                Err(RuntimeConfigurationError::InvalidDocument(
                    "scopeAllowlist entries must be non-empty RFC 6749 scope-token strings",
                ))
            }
        })
        .collect::<Result<Vec<_>, _>>()
        .and_then(reject_duplicate_scopes)
}

fn reject_duplicate_scopes(scopes: Vec<String>) -> Result<Vec<String>, RuntimeConfigurationError> {
    let mut seen = std::collections::BTreeSet::new();
    if scopes.iter().all(|scope| seen.insert(scope.clone())) {
        Ok(scopes)
    } else {
        Err(RuntimeConfigurationError::InvalidDocument(
            "scopeAllowlist entries must be unique",
        ))
    }
}

pub(super) fn parse_key_store(
    key_store: &KeyStoreDocument,
) -> Result<RuntimeKeyStoreConfiguration, RuntimeConfigurationError> {
    let key_store_type = key_store.key_store_type.trim();
    if key_store_type != "databaseEncrypted" {
        return Err(RuntimeConfigurationError::InvalidDocument(
            "keyStore.type must be databaseEncrypted",
        ));
    }
    let key_store_type = key_store_type.to_string();
    let configuration_object =
        key_store
            .configuration
            .as_object()
            .ok_or(RuntimeConfigurationError::InvalidDocument(
                "keyStore.configuration must be an object",
            ))?;
    if key_store_public_config_contains_sensitive_key(&key_store.configuration) {
        return Err(RuntimeConfigurationError::InvalidDocument(
            "keyStore.configuration must not contain secret material",
        ));
    }
    if !configuration_object.is_empty() {
        return Err(RuntimeConfigurationError::InvalidDocument(
            "keyStore.configuration must be empty for databaseEncrypted",
        ));
    }

    Ok(RuntimeKeyStoreConfiguration {
        key_store_type,
        configuration: serde_json::Value::Object(configuration_object.clone()),
        redacted: key_store.redacted,
    })
}

fn key_store_public_config_contains_sensitive_key(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => map.iter().any(|(key, value)| {
            is_sensitive_key_store_public_config_key(key)
                || key_store_public_config_contains_sensitive_key(value)
        }),
        serde_json::Value::Array(values) => values
            .iter()
            .any(key_store_public_config_contains_sensitive_key),
        _ => false,
    }
}

fn is_sensitive_key_store_public_config_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_lowercase())
        .collect();
    [
        "secret",
        "password",
        "token",
        "credential",
        "privatekey",
        "keyhandle",
        "apikey",
        "accesskey",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

use super::parse_configuration_document_v1;
use super::state::RuntimeConfigurationState;
use super::validation::{
    parse_key_store, parse_scope_allowlist, validate_runtime_configuration_document,
    validate_runtime_federation_policy,
};
use crate::runtime_configuration::RuntimeConfigurationError;

pub fn parse_runtime_configuration_document(
    document: &serde_json::Value,
    issuer_host: &str,
    issuer_url: &str,
) -> Result<RuntimeConfigurationState, RuntimeConfigurationError> {
    let document = parse_configuration_document_v1(document)
        .map_err(RuntimeConfigurationError::InvalidDocumentShape)?;
    validate_runtime_configuration_document(&document, issuer_host, issuer_url)?;
    let policy = document.policy;
    validate_runtime_federation_policy(&policy, issuer_url)?;
    let scope_allowlist = parse_scope_allowlist(&document.scope_allowlist)?;
    let key_store = parse_key_store(&document.key_store)?;

    Ok(RuntimeConfigurationState {
        policy,
        scope_allowlist,
        key_store,
    })
}

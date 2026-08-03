use super::configuration_federation::FederationConfigurationAuditSnapshot;
use super::{error_response, sha256_hex, ManagementEnvironmentScope};
use crate::management::types::*;
use axum::{http::StatusCode, response::Response};
use uuid::Uuid;

mod default_policy;
mod parser;
mod policy_patch_builder;
mod policy_sql;
mod policy_validation;
pub(super) use default_policy::default_policy_document;
pub(super) use parser::{
    load_policy_from_configuration_snapshot, parse_activated_environment_configuration,
    require_configuration_policy_for_request, validate_configuration_document_for_environment,
    validate_configuration_version_document,
};
#[cfg(test)]
pub(super) use parser::{parse_configuration_policy_document, parse_configuration_scope_allowlist};
pub(super) use policy_patch_builder::{build_policy_patch_configuration, policy_patch_comment};
pub(super) use policy_sql::UPDATE_ENVIRONMENT_POLICY_SQL;
pub(super) use policy_validation::validate_patched_policy;

#[derive(Clone, Debug)]
pub(super) struct PreparedConfigurationDocument {
    pub(super) hash: String,
    pub(super) document: String,
}

#[derive(Clone, Debug)]
pub(super) struct LockedEnvironmentMutationContext {
    pub(super) scope: ManagementEnvironmentScope,
    pub(super) name: String,
    pub(super) slug: String,
    pub(super) issuer_host: String,
    pub(super) issuer_url: String,
    pub(super) created_at: String,
    pub(super) active_configuration_version_id: Uuid,
}

#[derive(Clone, Debug)]
pub(super) struct EnvironmentConfigurationState {
    pub(super) policy: PolicyDocument,
    pub(super) scope_allowlist: Vec<String>,
    pub(super) key_store_type: String,
    pub(super) key_store_configuration: serde_json::Value,
    pub(super) key_store_redacted: bool,
}

#[derive(Clone, Debug)]
pub(super) struct ActivatedEnvironmentConfiguration {
    pub(super) configuration_document: serde_json::Value,
    pub(super) state: EnvironmentConfigurationState,
    pub(super) audit_snapshot: FederationConfigurationAuditSnapshot,
}

#[derive(Clone, Debug)]
pub(super) struct PolicyPatchDraft {
    pub(super) configuration: ActivatedEnvironmentConfiguration,
    pub(super) downgraded_fields: Vec<&'static str>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ConfigurationVersionTransition {
    pub(super) from_configuration_version_id: Uuid,
    pub(super) to_configuration_version_id: Uuid,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ConfigurationVersionAuditContext<'a> {
    pub(super) scope: ManagementEnvironmentScope,
    pub(super) administrator_id: Uuid,
    pub(super) request_id: &'a str,
    pub(super) transition: ConfigurationVersionTransition,
}

pub(super) fn prepare_configuration_document(
    configuration_document: &serde_json::Value,
    request_id: &str,
) -> Result<PreparedConfigurationDocument, Response> {
    let document = crate::runtime_configuration::serialize_canonical_configuration_document_v1(
        configuration_document,
    )
    .map_err(|_| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "configurationDocument must be a strict schemaVersion=1 document",
            None,
            Some(request_id),
        )
    })?;
    Ok(PreparedConfigurationDocument {
        hash: sha256_hex(document.as_bytes()),
        document,
    })
}

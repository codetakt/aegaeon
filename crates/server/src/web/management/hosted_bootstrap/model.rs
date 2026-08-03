use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct HostedBootstrapInput {
    pub issuer_url: String,
    pub owner_email: String,
    pub owner_password: String,
    pub team_name: String,
    pub team_slug: String,
    pub tenant_name: String,
    pub tenant_slug: String,
    pub tenant_region: String,
    pub environment_name: String,
    pub environment_slug: String,
    pub kms_region: String,
    pub kms_key_id: String,
    pub kms_kid: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostedBootstrapOutput {
    pub status: HostedBootstrapStatus,
    pub issuer_host: String,
    pub issuer_url: String,
    pub team_id: Uuid,
    pub tenant_id: Uuid,
    pub environment_id: Uuid,
    pub configuration_version_id: Uuid,
    pub runtime_key_id: Uuid,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostedBootstrapStatus {
    Created,
    AlreadyInitialized,
}

pub(super) struct NormalizedHostedBootstrapInput {
    pub(super) issuer_host: String,
    pub(super) issuer_url: String,
    pub(super) owner_email: String,
    pub(super) owner_password: String,
    pub(super) team_name: String,
    pub(super) team_slug: String,
    pub(super) tenant_name: String,
    pub(super) tenant_slug: String,
    pub(super) tenant_region: String,
    pub(super) environment_name: String,
    pub(super) environment_slug: String,
    pub(super) kms_region: String,
    pub(super) kms_key_id: String,
    pub(super) kms_kid: String,
}

pub(super) struct ExistingBootstrap {
    pub(super) team_id: Uuid,
    pub(super) tenant_id: Uuid,
    pub(super) environment_id: Uuid,
    pub(super) configuration_version_id: Uuid,
    pub(super) runtime_key_id: Uuid,
}

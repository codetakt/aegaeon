mod environment_creation;
mod initial_config;
mod input;

use super::configuration_documents::{
    EnvironmentConfigurationState, PreparedConfigurationDocument,
};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub(super) struct CreateTenantInput {
    pub(super) slug: String,
    pub(super) name: String,
    pub(super) region: String,
}

#[derive(Clone, Debug)]
pub(super) struct CreateEnvironmentInput {
    pub(super) slug: String,
    pub(super) name: String,
}

#[derive(Clone, Debug)]
pub(super) struct InitialEnvironmentConfiguration {
    pub(super) issuer_host: String,
    pub(super) issuer_url: String,
    prepared_document: PreparedConfigurationDocument,
    state: EnvironmentConfigurationState,
}

#[derive(Clone, Debug)]
pub(super) struct CreatedEnvironmentState {
    pub(super) environment_id: Uuid,
    pub(super) configuration_version_id: Uuid,
    pub(super) created_at: String,
    pub(super) updated_at: String,
}

pub(super) use environment_creation::{
    create_environment_with_initial_configuration, lock_environment_creation_parent,
};
pub(super) use initial_config::build_initial_environment_configuration;
pub(super) use input::{
    parse_create_environment_input, parse_create_tenant_input, parse_update_name,
};

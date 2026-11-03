use crate::attribute_mapping::profile::ProfileMapping;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const PROFILE: &str = "lti-resource-link-1.3";
pub const CLAIM_PREFIX: &str = "https://purl.imsglobal.org/spec/lti/claim/";
pub const INTENT_TTL_SECONDS: i64 = 300;
pub const TOKEN_TTL_SECONDS: i64 = 60;
pub const MAX_CONFIGURATION_BYTES: usize = 262_144;

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Active,
    #[default]
    Disabled,
    Retired,
}

fn enabled() -> bool {
    true
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecurityPolicy {
    #[serde(default = "enabled")]
    pub require_consent: bool,
    #[serde(default = "enabled")]
    pub require_dpop: bool,
    #[serde(default = "enabled")]
    pub staged_activation: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            require_consent: true,
            require_dpop: true,
            staged_activation: true,
        }
    }
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolConfiguration {
    pub schema_version: u32,
    pub name: String,
    pub initiate_login_uri: String,
    pub redirect_uris: BTreeSet<String>,
    #[serde(default)]
    pub status: Lifecycle,
    #[serde(default)]
    pub security: SecurityPolicy,
    pub deployments: Vec<Deployment>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub mapping: ProfileMapping,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Deployment {
    pub id: String,
    #[serde(default)]
    pub status: Lifecycle,
    pub producers: BTreeSet<String>,
    pub allowed_roles: BTreeSet<String>,
    pub resource_links: Vec<ResourceLink>,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceLink {
    pub id: String,
    #[serde(default)]
    pub status: Lifecycle,
    pub target_link_uri: String,
    pub context: LaunchContext,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaunchContext {
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub types: BTreeSet<String>,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateLaunch {
    pub client_id: String,
    pub deployment_id: String,
    pub resource_link_id: String,
    pub user_id: String,
    pub roles: BTreeSet<String>,
}

impl ToolConfiguration {
    /// Resolve only currently active objects from one configuration revision.
    ///
    /// # Errors
    /// Rejects missing or inactive registration, deployment or resource link.
    pub fn placement(
        &self,
        deployment: &str,
        link: &str,
    ) -> Result<(&Deployment, &ResourceLink), super::LtiError> {
        if self.status != Lifecycle::Active {
            return Err(super::LtiError::Denied);
        }
        let deployment = self
            .deployments
            .iter()
            .find(|entry| entry.id == deployment && entry.status == Lifecycle::Active)
            .ok_or(super::LtiError::Denied)?;
        let link = deployment
            .resource_links
            .iter()
            .find(|entry| entry.id == link && entry.status == Lifecycle::Active)
            .ok_or(super::LtiError::Denied)?;
        Ok((deployment, link))
    }
}

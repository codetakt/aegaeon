//! Explicit caller-to-resource authority for the client-credentials grant.
//! Target names and aliases are owned by the shared token-exchange catalog.
use serde::{Deserialize, Serialize};

mod authorization;
mod grant;
#[cfg(test)]
mod tests;
mod validation;

pub use grant::{
    AuthorizedClientCredentials, ClientCredentialsGrant, ClientCredentialsRegistration,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClientCredentialsPolicy {
    pub version: u32,
    pub resource_servers: Vec<ClientCredentialsResourceServer>,
    pub rules: Vec<ClientCredentialsRule>,
}

impl Default for ClientCredentialsPolicy {
    fn default() -> Self {
        Self {
            version: 1,
            resource_servers: Vec::new(),
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClientCredentialsResourceServer {
    pub target_audience: String,
    pub introspection_clients: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClientCredentialsRule {
    pub client_id: String,
    pub target_audience: String,
    pub scopes: Vec<String>,
    pub default_scopes: Vec<String>,
    pub default_target: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientCredentialsAuthorizationError {
    InvalidPolicy,
    InvalidTarget,
    InvalidScope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClientCredentialsSelection {
    pub(crate) audience: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) context_digest: String,
    pub(crate) introspection_clients: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClientCredentialsSelectionContext {
    pub(crate) scopes: Vec<String>,
    pub(crate) context_digest: String,
    pub(crate) introspection_clients: Vec<String>,
}

//! Issuer-owned RFC 8693 target and scope authority. No authority is inferred from JWT claims.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

mod grant;
mod validation;
pub use grant::{ExchangeAuthorizationError, ExchangeGrant, ExchangeRoot};
#[cfg(test)]
mod tests;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TokenExchangePolicy {
    pub version: u32,
    pub targets: Vec<ExchangeTarget>,
    pub rules: Vec<ExchangeRule>,
}

impl Default for TokenExchangePolicy {
    fn default() -> Self {
        Self {
            version: 1,
            targets: Vec::new(),
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExchangeTarget {
    pub audience: String,
    pub resource_aliases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExchangeRule {
    pub client_id: String,
    pub source_audience: String,
    pub target_audience: String,
    pub scopes: Vec<ExchangeScope>,
    pub default_scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExchangeScope {
    pub target_scope: String,
    pub source_scopes: Vec<String>,
}

impl TokenExchangePolicy {
    fn digest(&self) -> Option<String> {
        serde_json::to_vec(self)
            .ok()
            .map(|bytes| aegaeon_crypto::hash::sha256_hex(&bytes))
    }

    /// All occurrences contribute. Distinct targets are outside this single-target profile.
    pub fn resolve_target(
        &self,
        params: &[(String, String)],
    ) -> Result<Option<String>, &'static str> {
        let mut selected = None;
        for (key, value) in params {
            let target = match key.as_str() {
                "audience" => self.targets.iter().find(|target| target.audience == *value),
                "resource" => self
                    .targets
                    .iter()
                    .find(|target| target.resource_aliases.contains(value)),
                _ => continue,
            }
            .ok_or("unregistered token exchange target")?;
            if selected.as_ref().is_some_and(|old| old != &target.audience) {
                return Err("multiple distinct exchange targets are not supported");
            }
            selected = Some(target.audience.clone());
        }
        Ok(selected)
    }
}

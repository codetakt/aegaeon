use super::ClientCredentialsPolicy;
use crate::policy::token_exchange::TokenExchangePolicy;
use std::collections::BTreeSet;

fn identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.chars().any(char::is_whitespace)
        && !value.chars().any(char::is_control)
}

fn scope(value: &str) -> bool {
    value.len() <= 256
        && !matches!(value, "openid" | "offline_access")
        && crate::oauth_scope::parse_scope_string(value).is_ok_and(|values| values.len() == 1)
}

fn unique(values: &[String], valid: impl Fn(&str) -> bool) -> bool {
    values.len() <= 128
        && values.iter().all(|value| valid(value))
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

impl ClientCredentialsPolicy {
    pub fn validate(&self, catalog: &TokenExchangePolicy) -> Result<(), &'static str> {
        catalog.validate()?;
        if self.version != 1 || self.resource_servers.len() > 64 || self.rules.len() > 256 {
            return Err("invalid clientCredentials version or collection limit");
        }
        let targets: BTreeSet<_> = catalog
            .targets
            .iter()
            .map(|target| &target.audience)
            .collect();
        let mut bindings = BTreeSet::new();
        for binding in &self.resource_servers {
            if !targets.contains(&binding.target_audience)
                || !bindings.insert(&binding.target_audience)
                || !unique(&binding.introspection_clients, identity)
            {
                return Err("invalid or ambiguous clientCredentials resource-server binding");
            }
        }
        let mut routes = BTreeSet::new();
        let mut defaults = BTreeSet::new();
        for rule in &self.rules {
            if !identity(&rule.client_id)
                || !bindings.contains(&rule.target_audience)
                || !routes.insert((&rule.client_id, &rule.target_audience))
                || (rule.default_target && !defaults.insert(&rule.client_id))
            {
                return Err("invalid or ambiguous clientCredentials rule");
            }
            if rule.scopes.is_empty()
                || !unique(&rule.scopes, scope)
                || !unique(&rule.default_scopes, scope)
                || rule
                    .default_scopes
                    .iter()
                    .any(|value| !rule.scopes.contains(value))
            {
                return Err("invalid clientCredentials scopes or defaults");
            }
        }
        Ok(())
    }
}

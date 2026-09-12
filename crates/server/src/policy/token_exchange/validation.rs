use super::*;

fn identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.chars().any(char::is_whitespace)
        && !value.chars().any(char::is_control)
}

fn scope(value: &str) -> bool {
    value.len() <= 256
        && crate::oauth_scope::parse_scope_string(value).is_ok_and(|values| values.len() == 1)
}

fn unique(values: &[String], valid: impl Fn(&str) -> bool) -> bool {
    values.len() <= 128
        && values.iter().all(|value| valid(value))
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

impl TokenExchangePolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != 1 || self.targets.len() > 64 || self.rules.len() > 256 {
            return Err("invalid tokenExchange version or collection limit");
        }
        let mut names = BTreeSet::new();
        let mut aliases = BTreeSet::new();
        for target in &self.targets {
            if !identity(&target.audience)
                || !names.insert(&target.audience)
                || !unique(&target.resource_aliases, |value| {
                    identity(value)
                        && url::Url::parse(value).is_ok_and(|url| url.fragment().is_none())
                })
                || target
                    .resource_aliases
                    .iter()
                    .any(|alias| !aliases.insert(alias))
            {
                return Err("invalid or ambiguous exchange target");
            }
        }
        // An audience and a resource alias may share a spelling only when both
        // identify the same target. Check after collecting every audience so
        // validation does not depend on target order.
        for target in &self.targets {
            if target
                .resource_aliases
                .iter()
                .any(|alias| alias != &target.audience && names.contains(alias))
            {
                return Err("invalid or ambiguous exchange target");
            }
        }
        let mut routes = BTreeSet::new();
        for rule in &self.rules {
            if !identity(&rule.client_id)
                || !identity(&rule.source_audience)
                || !names.contains(&rule.target_audience)
                || !routes.insert((
                    &rule.client_id,
                    &rule.source_audience,
                    &rule.target_audience,
                ))
                || rule.scopes.is_empty()
                || rule.scopes.len() > 128
            {
                return Err("invalid or ambiguous exchange rule");
            }
            let mut scopes = BTreeSet::new();
            for mapping in &rule.scopes {
                if !scope(&mapping.target_scope)
                    || matches!(mapping.target_scope.as_str(), "openid" | "offline_access")
                    || !scopes.insert(&mapping.target_scope)
                    || mapping.source_scopes.is_empty()
                    || !unique(&mapping.source_scopes, scope)
                {
                    return Err("invalid exchange scope mapping");
                }
            }
            if !unique(&rule.default_scopes, scope)
                || rule.default_scopes.iter().any(|s| !scopes.contains(s))
            {
                return Err("exchange defaults must be unique mapped target scopes");
            }
        }
        Ok(())
    }
}

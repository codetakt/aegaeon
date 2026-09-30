use super::{
    ClientCredentialsAuthorizationError as Error, ClientCredentialsPolicy,
    ClientCredentialsSelection, ClientCredentialsSelectionContext,
};
use crate::policy::token_exchange::TokenExchangePolicy;

impl ClientCredentialsPolicy {
    /// Resolve explicit selectors or the caller's explicit default, then apply both ceilings.
    pub(crate) fn authorize(
        &self,
        catalog: &TokenExchangePolicy,
        client_id: &str,
        registered_scopes: &[String],
        params: &[(String, String)],
        requested_scope: Option<&str>,
    ) -> Result<ClientCredentialsSelection, Error> {
        self.validate(catalog).map_err(|_| Error::InvalidPolicy)?;
        if ["audience", "resource"].iter().any(|key| {
            params
                .iter()
                .filter(|(name, _)| name.as_str() == *key)
                .count()
                > 1
        }) {
            return Err(Error::InvalidTarget);
        }
        let audience = catalog
            .resolve_target(params)
            .map_err(|_| Error::InvalidTarget)?
            .or_else(|| {
                self.rules
                    .iter()
                    .find(|rule| rule.client_id == client_id && rule.default_target)
                    .map(|rule| rule.target_audience.clone())
            })
            .ok_or(Error::InvalidTarget)?;
        let rule = self
            .rules
            .iter()
            .find(|rule| rule.client_id == client_id && rule.target_audience == audience)
            .ok_or(Error::InvalidTarget)?;
        let mut scopes = match requested_scope {
            Some(value) => {
                crate::oauth_scope::parse_scope_string(value).map_err(|_| Error::InvalidScope)?
            }
            None => rule.default_scopes.clone(),
        };
        if scopes.is_empty()
            || scopes
                .iter()
                .any(|scope| !rule.scopes.contains(scope) || !registered_scopes.contains(scope))
        {
            return Err(Error::InvalidScope);
        }
        scopes.sort();
        scopes.dedup();
        let context = self.selected_context(catalog, client_id, &audience)?;
        Ok(ClientCredentialsSelection {
            audience,
            scopes,
            context_digest: context.context_digest,
            introspection_clients: context.introspection_clients,
        })
    }

    /// Selected authority only: unrelated policy edits do not revoke this context.
    pub(crate) fn selected_context(
        &self,
        catalog: &TokenExchangePolicy,
        client_id: &str,
        audience: &str,
    ) -> Result<ClientCredentialsSelectionContext, Error> {
        self.validate(catalog).map_err(|_| Error::InvalidPolicy)?;
        let mut target = catalog
            .targets
            .iter()
            .find(|target| target.audience == audience)
            .cloned()
            .ok_or(Error::InvalidTarget)?;
        let mut rule = self
            .rules
            .iter()
            .find(|rule| rule.client_id == client_id && rule.target_audience == audience)
            .cloned()
            .ok_or(Error::InvalidTarget)?;
        let mut binding = self
            .resource_servers
            .iter()
            .find(|binding| binding.target_audience == audience)
            .cloned()
            .ok_or(Error::InvalidTarget)?;
        target.resource_aliases.sort();
        rule.scopes.sort();
        rule.default_scopes.sort();
        binding.introspection_clients.sort();
        let bytes = serde_json::to_vec(&(
            "client-credentials-context-v1",
            self.version,
            catalog.version,
            &target,
            &rule,
            &binding,
        ))
        .map_err(|_| Error::InvalidPolicy)?;
        Ok(ClientCredentialsSelectionContext {
            scopes: rule.scopes,
            context_digest: aegaeon_crypto::hash::sha256_hex(&bytes),
            introspection_clients: binding.introspection_clients,
        })
    }
}

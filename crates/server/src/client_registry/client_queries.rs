use aegaeon_jose::jwk::KeyMaterial;

use super::jwks_fetch::fetch_jwks_with_state;
use super::jwks_validation::select_jwk;
use super::{
    log_client_registry_state_error, ClientRegistry, ClientRegistryStateError, ResolvedJwkParts,
};

impl ClientRegistry {
    #[must_use = "handle the registry result to preserve backend failures"]
    pub fn try_validate_scope_subset(
        &self,
        client_id: &str,
        requested: &[String],
    ) -> Result<bool, ClientRegistryStateError> {
        Ok(self.try_get(client_id)?.is_some_and(|c| {
            requested
                .iter()
                .all(|s| c.allowed_scopes.iter().any(|a| a == s))
        }))
    }

    #[must_use]
    pub fn validate_scope_subset(&self, client_id: &str, requested: &[String]) -> bool {
        self.try_validate_scope_subset(client_id, requested)
            .unwrap_or_else(|error| {
                log_client_registry_state_error("validate_scope_subset", &error);
                false
            })
    }

    #[must_use = "handle the registry result to preserve backend failures"]
    pub fn try_allows_grant(
        &self,
        client_id: &str,
        grant_type: &str,
    ) -> Result<bool, ClientRegistryStateError> {
        Ok(self
            .try_get(client_id)?
            .is_some_and(|c| c.allowed_grant_types.iter().any(|g| g == grant_type)))
    }

    #[must_use]
    pub fn allows_grant(&self, client_id: &str, grant_type: &str) -> bool {
        self.try_allows_grant(client_id, grant_type)
            .unwrap_or_else(|error| {
                log_client_registry_state_error("allows_grant", &error);
                false
            })
    }

    /// Resolve a JWK for a client from its `jwks_uri`, selecting by `kid` when provided.
    /// Exposed for integration tests.
    #[must_use = "handle the registry result to preserve backend failures"]
    pub fn try_resolve_client_jwk(
        &self,
        client_id: &str,
        kid: Option<&str>,
    ) -> Result<Option<ResolvedJwkParts>, ClientRegistryStateError> {
        let Some(reg) = self.try_get(client_id)? else {
            return Ok(None);
        };
        if let Some(inline_jwks) = &reg.inline_jwks {
            let Some(jwk) = inline_jwks.select(kid) else {
                return Ok(None);
            };
            let parts = match &jwk.material {
                KeyMaterial::Rsa { n, e } => (
                    jwk.key_type.clone(),
                    None,
                    None,
                    Some(n.clone()),
                    Some(e.clone()),
                ),
                KeyMaterial::Ec { x, y, .. } => (
                    jwk.key_type.clone(),
                    Some(x.clone()),
                    Some(y.clone()),
                    None,
                    None,
                ),
            };
            return Ok(Some(parts));
        }
        let Some(uri) = reg.jwks_uri else {
            return Ok(None);
        };
        let Some(jwks) = fetch_jwks_with_state(&self.jwks_state, &self.jwks_policy, &uri) else {
            return Ok(None);
        };
        let Some(jwk) = select_jwk(&jwks, kid) else {
            return Ok(None);
        };
        Ok(Some((jwk.kty, jwk.x, jwk.y, jwk.n, jwk.e)))
    }

    #[must_use]
    pub fn resolve_client_jwk(
        &self,
        client_id: &str,
        kid: Option<&str>,
    ) -> Option<ResolvedJwkParts> {
        self.try_resolve_client_jwk(client_id, kid)
            .unwrap_or_else(|error| {
                log_client_registry_state_error("resolve_client_jwk", &error);
                None
            })
    }
}

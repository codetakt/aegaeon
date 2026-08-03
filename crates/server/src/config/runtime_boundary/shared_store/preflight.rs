use super::inventory::SharedRuntimeStoreRequirement;
use super::url::{RedisStoreUrl, SharedRuntimeStoreUrl};
use crate::config::{ConfigError, ServerConfig};

pub fn require_shared_runtime_store_url(
    surface: &str,
    env_key: &str,
) -> Result<SharedRuntimeStoreUrl, ConfigError> {
    if let Some(url) = RedisStoreUrl::optional_from_env(env_key)? {
        return Ok(SharedRuntimeStoreUrl::new(env_key, url));
    }

    Err(ConfigError::InvalidValue {
        key: env_key.to_string(),
        value: "<missing>".to_string(),
        reason: format!(
            "{surface} requires DB/Redis-backed shared runtime state; configure {env_key}"
        ),
    })
}

impl SharedRuntimeStoreRequirement {
    fn is_satisfied(self) -> Result<bool, ConfigError> {
        shared_redis_store_env_configured(self.primary_env)
    }
}

fn shared_redis_store_env_configured(key: &str) -> Result<bool, ConfigError> {
    RedisStoreUrl::optional_from_env(key).map(|url| url.is_some())
}

impl ServerConfig {
    fn missing_shared_runtime_store_requirements(
        &self,
        oidc_enabled: bool,
    ) -> Result<Vec<String>, ConfigError> {
        let missing = self
            .shared_runtime_store_requirements(oidc_enabled)?
            .into_iter()
            .map(|requirement| requirement.is_satisfied().map(|ok| (requirement, ok)))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|(_, ok)| !ok)
            .map(|(requirement, _)| requirement.describe())
            .collect();
        Ok(missing)
    }

    pub(in crate::config) fn validate_shared_runtime_store_preflight(
        &self,
        oidc_enabled: bool,
    ) -> Result<(), ConfigError> {
        let missing = self.missing_shared_runtime_store_requirements(oidc_enabled)?;

        if missing.is_empty() {
            return Ok(());
        }

        Err(ConfigError::InvalidValue {
            key: "shared_runtime_stores".to_string(),
            value: "<missing>".to_string(),
            reason: format!(
                "supported deployments require shared DB/Redis-backed stores for all competing runtime state; missing shared-store preflight variables: {}",
                missing.join(", ")
            ),
        })
    }
}

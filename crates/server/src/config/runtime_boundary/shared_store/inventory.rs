use crate::config::{ConfigError, ServerConfig};

#[derive(Clone, Copy, Debug)]
pub(in crate::config) struct SharedRuntimeStoreRequirement {
    pub(in crate::config) surface: &'static str,
    pub(in crate::config) primary_env: &'static str,
}

impl SharedRuntimeStoreRequirement {
    pub(in crate::config) fn describe(self) -> String {
        format!("{} ({})", self.surface, self.primary_env)
    }
}

impl ServerConfig {
    pub(in crate::config) fn shared_runtime_store_requirements(
        &self,
        _oidc_enabled: bool,
    ) -> Result<Vec<SharedRuntimeStoreRequirement>, ConfigError> {
        // Production security/continuation stores are selected through the
        // preflighted primary PostgreSQL database and one grant-store identity.
        // Legacy Redis constructors are retained for compatibility fixtures.
        Ok(Vec::new())
    }
}

use crate::config::{
    configured_oidc_startup_key_material_env_keys, configured_oidc_startup_policy_env_keys,
    configured_startup_managed_policy_env_keys, ConfigError, ServerConfig,
};

impl ServerConfig {
    pub fn validate_runtime_boundaries(&self, oidc_enabled: bool) -> Result<(), ConfigError> {
        self.validate_management_database_startup_environment_boundary()?;
        let jwt_runtime = self.jwt_runtime();
        self.validate_runtime_boundaries_with_key_material(
            oidc_enabled,
            false,
            jwt_runtime.access_tokens_enabled() || jwt_runtime.introspection_enabled(),
        )
    }

    pub fn validate_runtime_boundaries_with_oidc_key_material(
        &self,
        oidc_enabled: bool,
        oidc_uses_process_local_key_material: bool,
    ) -> Result<(), ConfigError> {
        let jwt_runtime = self.jwt_runtime();
        self.validate_runtime_boundaries_with_key_material(
            oidc_enabled,
            oidc_uses_process_local_key_material,
            jwt_runtime.access_tokens_enabled() || jwt_runtime.introspection_enabled(),
        )
    }

    pub fn validate_runtime_boundaries_with_key_material(
        &self,
        oidc_enabled: bool,
        oidc_uses_unmanaged_key_material: bool,
        oauth_jwt_uses_unmanaged_key_material: bool,
    ) -> Result<(), ConfigError> {
        self.validate_shared_runtime_store_preflight(oidc_enabled)?;
        self.validate_management_database_key_material_boundary(
            oidc_uses_unmanaged_key_material,
            oauth_jwt_uses_unmanaged_key_material,
        )
    }

    pub(in crate::config) fn validate_management_database_startup_environment_boundary(
        &self,
    ) -> Result<(), ConfigError> {
        let key_material_keys = configured_oidc_startup_key_material_env_keys()?;
        if !key_material_keys.is_empty() {
            let first_key = key_material_keys[0];
            return Err(ConfigError::InvalidValue {
                key: first_key.to_string(),
                value: "<configured>".to_string(),
                reason: format!(
                    "OIDC signing and request-object key material must come from the active runtime_keys snapshot; remove startup key-material environment variables: {}",
                    key_material_keys.join(", ")
                ),
            });
        }

        let policy_keys = configured_oidc_startup_policy_env_keys()?;
        if !policy_keys.is_empty() {
            let first_key = policy_keys[0];
            return Err(ConfigError::InvalidValue {
                key: first_key.to_string(),
                value: "<configured>".to_string(),
                reason: format!(
                    "OIDC runtime policy must come from the active management configuration snapshot; remove startup OIDC policy environment variables: {}",
                    policy_keys.join(", ")
                ),
            });
        }

        let managed_policy_keys = configured_startup_managed_policy_env_keys()?;
        if !managed_policy_keys.is_empty() {
            let first_key = managed_policy_keys[0];
            return Err(ConfigError::InvalidValue {
                key: first_key.to_string(),
                value: "<configured>".to_string(),
                reason: format!(
                    "runtime policy must come from the active management configuration snapshot; remove startup policy environment variables: {}",
                    managed_policy_keys.join(", ")
                ),
            });
        }

        Ok(())
    }

    fn validate_management_database_key_material_boundary(
        &self,
        oidc_uses_unmanaged_key_material: bool,
        oauth_jwt_uses_unmanaged_key_material: bool,
    ) -> Result<(), ConfigError> {
        let unmanaged_key_surfaces = [
            (
                oidc_uses_unmanaged_key_material,
                "OIDC ID Token signing / Request Object decryption",
            ),
            (
                self.jwt_runtime().access_tokens_enabled() && oauth_jwt_uses_unmanaged_key_material,
                "JWT access tokens",
            ),
            (
                self.jwt_runtime().introspection_enabled() && oauth_jwt_uses_unmanaged_key_material,
                "JWT introspection responses",
            ),
        ]
        .into_iter()
        .filter_map(|(enabled, surface)| enabled.then_some(surface))
        .collect::<Vec<_>>();

        if unmanaged_key_surfaces.is_empty() {
            return Ok(());
        }

        Err(ConfigError::InvalidValue {
            key: "runtime_keys".to_string(),
            value: "<unmanaged>".to_string(),
            reason: format!(
                "shared key material must come from the active management runtime_keys snapshot; unmanaged key material is not allowed for {}",
                unmanaged_key_surfaces.join(", ")
            ),
        })
    }
}

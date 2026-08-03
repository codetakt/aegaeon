use super::runtime_boundary::reject_raw_json_backend_override_envs;
use super::{
    try_env_flag, try_required_env_flag, BootstrapConfig, ConfigError, DatabaseConfig,
    RuntimeStateBoundaryConfig, TransportSecurityConfig,
};
use crate::policy::{SecurityPolicy, SenderConstraint};

fn management_database_bootstrap_security_policy_from_env() -> Result<SecurityPolicy, ConfigError> {
    let mut policy = SecurityPolicy::default()
        .with_sender_constraint(SenderConstraint::None)
        .with_sender_binding_enforcement(false);
    policy.transport.enforce_trusted_proxy =
        try_env_flag("AEGAEON_POLICY_REQUIRE_TRUSTED_PROXY", true)?;
    policy.transport.tls_validation_required = try_required_env_flag(
        "AEGAEON_POLICY_REQUIRE_TLS_VALIDATION",
        true,
        "TLS validation cannot be disabled by the process environment",
    )?;
    Ok(policy)
}

impl BootstrapConfig {
    pub fn try_from_env() -> Result<Self, ConfigError> {
        super::reject_removed_database_runtime_envs()?;
        super::validate_authorization_code_grant_commit_store_topology()?;
        let runtime_state_boundary = RuntimeStateBoundaryConfig::try_from_env()?;
        Self::try_management_database_bootstrap_from_env(runtime_state_boundary)
    }

    pub(super) fn try_management_database_bootstrap_from_env(
        runtime_state_boundary: RuntimeStateBoundaryConfig,
    ) -> Result<Self, ConfigError> {
        let database = DatabaseConfig::try_from_env()?;
        let bootstrap = Self {
            database,
            transport: TransportSecurityConfig::try_from_env()?,
            security_policy: management_database_bootstrap_security_policy_from_env()?,
            runtime_state_boundary,
        };

        let mut cfg = bootstrap.clone().into_runtime_baseline();
        cfg.dpop_strict = false;
        cfg.require_dpop_nonce = false;
        cfg.validate_management_database_startup_environment_boundary()?;
        reject_raw_json_backend_override_envs()?;
        cfg.validate_shared_runtime_store_preflight(false)?;
        Ok(bootstrap)
    }
}

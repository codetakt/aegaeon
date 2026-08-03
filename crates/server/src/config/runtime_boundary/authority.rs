use crate::config::{
    ConfigError, DEPLOYMENT_MODE_ENV, REMOVED_EPHEMERAL_RUNTIME_STATE_ENV,
    REMOVED_UNSHARED_RUNTIME_STATE_ENV,
};
use std::env;

#[derive(Clone, Debug, Default)]
pub struct RuntimeStateBoundaryConfig;

impl RuntimeStateBoundaryConfig {
    pub fn try_from_env() -> Result<Self, ConfigError> {
        reject_removed_deployment_mode_env()?;
        reject_removed_unshared_runtime_state_env()?;
        reject_removed_ephemeral_runtime_state_env()?;
        Ok(Self)
    }
}

#[doc(hidden)]
#[must_use]
pub fn test_runtime_helpers_allowed_by_build() -> bool {
    cfg!(test)
}

fn reject_removed_deployment_mode_env() -> Result<(), ConfigError> {
    match env::var(DEPLOYMENT_MODE_ENV) {
        Ok(value) => Err(ConfigError::InvalidValue {
            key: DEPLOYMENT_MODE_ENV.to_string(),
            value,
            reason: "the deployment mode selector was removed; all supported deployments require PostgreSQL plus DB/Redis-backed shared runtime state".to_string(),
        }),
        Err(env::VarError::NotPresent) => Ok(()),
        Err(env::VarError::NotUnicode(_)) => Err(ConfigError::NonUnicode {
            key: DEPLOYMENT_MODE_ENV.to_string(),
        }),
    }
}

fn reject_removed_unshared_runtime_state_env() -> Result<(), ConfigError> {
    match env::var(REMOVED_UNSHARED_RUNTIME_STATE_ENV) {
        Ok(value) => Err(ConfigError::InvalidValue {
            key: REMOVED_UNSHARED_RUNTIME_STATE_ENV.to_string(),
            value,
            reason: "this legacy acknowledgement was removed; configure DB/Redis-backed shared runtime stores for competing state instead".to_string(),
        }),
        Err(env::VarError::NotPresent) => Ok(()),
        Err(env::VarError::NotUnicode(_)) => Err(ConfigError::NonUnicode {
            key: REMOVED_UNSHARED_RUNTIME_STATE_ENV.to_string(),
        }),
    }
}

fn reject_removed_ephemeral_runtime_state_env() -> Result<(), ConfigError> {
    match env::var(REMOVED_EPHEMERAL_RUNTIME_STATE_ENV) {
        Ok(value) => Err(ConfigError::InvalidValue {
            key: REMOVED_EPHEMERAL_RUNTIME_STATE_ENV.to_string(),
            value,
            reason: "this legacy ephemeral runtime-state acknowledgement was removed; configure DB/Redis-backed shared runtime stores".to_string(),
        }),
        Err(env::VarError::NotPresent) => Ok(()),
        Err(env::VarError::NotUnicode(_)) => Err(ConfigError::NonUnicode {
            key: REMOVED_EPHEMERAL_RUNTIME_STATE_ENV.to_string(),
        }),
    }
}

use anyhow::Result;
use std::sync::Arc;

use aegaeon_server::config::ServerConfig;
use aegaeon_server::kms::{KeyManager, KeyManagerError, ManagedJwtKeyManager};
use aegaeon_server::runtime_keys::{RuntimeKeySet, RuntimeKeyUsage};

type RuntimeKeyManagerPair = (Arc<dyn KeyManager>, Option<Arc<dyn KeyManager>>);

fn managed_jwt_key_manager(
    runtime_keys: &RuntimeKeySet,
    usage: RuntimeKeyUsage,
) -> Result<Arc<dyn KeyManager>> {
    ManagedJwtKeyManager::try_from_runtime_keys(runtime_keys, usage)
        .map(|manager| Arc::new(manager) as Arc<dyn KeyManager>)
        .map_err(|err| {
            anyhow::anyhow!(
                "failed to initialize {} runtime key manager: {err}",
                usage.as_db_str()
            )
        })
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct DisabledKeyManager;

impl KeyManager for DisabledKeyManager {
    fn sign(&self, _msg: &[u8]) -> std::result::Result<Vec<u8>, KeyManagerError> {
        Err(KeyManagerError::KeyNotFound)
    }

    fn verify(&self, _msg: &[u8], _sig: &[u8]) -> std::result::Result<bool, KeyManagerError> {
        Err(KeyManagerError::KeyNotFound)
    }

    fn key_id(&self) -> String {
        "disabled".to_string()
    }

    fn jwt_signing_alg(&self) -> &'static str {
        "disabled"
    }

    fn rotate(&self) -> std::result::Result<(), KeyManagerError> {
        Err(KeyManagerError::KeyNotFound)
    }

    fn revoke(&self) -> std::result::Result<(), KeyManagerError> {
        Err(KeyManagerError::KeyNotFound)
    }
}

fn disabled_key_manager() -> Arc<dyn KeyManager> {
    Arc::new(DisabledKeyManager)
}

pub(super) fn runtime_key_managers(
    cfg: &ServerConfig,
    runtime_keys: &RuntimeKeySet,
) -> Result<RuntimeKeyManagerPair> {
    let jwt_runtime = cfg.jwt_runtime();
    let primary = if jwt_runtime.access_tokens_enabled() {
        managed_jwt_key_manager(runtime_keys, RuntimeKeyUsage::JwtAccessTokenSigning)?
    } else if jwt_runtime.introspection_enabled() {
        managed_jwt_key_manager(runtime_keys, RuntimeKeyUsage::JwtIntrospectionSigning)?
    } else {
        disabled_key_manager()
    };
    let introspection = (jwt_runtime.access_tokens_enabled()
        && jwt_runtime.introspection_enabled())
    .then(|| managed_jwt_key_manager(runtime_keys, RuntimeKeyUsage::JwtIntrospectionSigning))
    .transpose()?;
    Ok((primary, introspection))
}

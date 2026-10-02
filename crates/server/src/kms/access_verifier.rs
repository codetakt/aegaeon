//! Verification capability for access JWTs; no signing or private-key access.
use std::sync::Arc;

use super::managed::{managed_jwt_verification_key, ManagedJwtVerificationKey};
use super::{KeyManager, KeyManagerError};
use crate::runtime_keys::{RuntimeKeySet, RuntimeKeyUsage};

/// Explicit verification-only capability for access-token signatures.
/// Library callers supply the trust domain; production uses [`ManagedAccessTokenVerifier`].
pub trait AccessTokenVerifier: Send + Sync {
    /// Verify the exact JOSE key identifier and algorithm.
    ///
    /// # Errors
    ///
    /// Operational failures must return `OperationFailed`; unavailable or revoked keys
    /// may return `KeyNotFound` or `KeyRevoked` and are treated as invalid tokens.
    fn verify_access_token_signature(
        &self,
        kid: &str,
        alg: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, KeyManagerError>;
}

pub(crate) struct KeyManagerAccessTokenVerifier(pub(crate) Arc<dyn KeyManager>);

impl AccessTokenVerifier for KeyManagerAccessTokenVerifier {
    fn verify_access_token_signature(
        &self,
        kid: &str,
        alg: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, KeyManagerError> {
        self.0.verify_jwt_signature(kid, alg, message, signature)
    }
}

/// Public material restricted to `JwtAccessTokenSigning`, independent of signing flags.
/// Retiring keys remain eligible strictly before their configured expiry.
pub struct ManagedAccessTokenVerifier {
    keys: Vec<ManagedJwtVerificationKey>,
    now: fn() -> Result<i64, KeyManagerError>,
}

impl ManagedAccessTokenVerifier {
    /// Construct a view from validated runtime access keys without decrypting handles.
    /// An empty or retiring-only access-key set is supported.
    ///
    /// # Errors
    ///
    /// Invalid configured public material is an initialization failure.
    pub fn try_from_runtime_keys(keys: &RuntimeKeySet) -> Result<Self, KeyManagerError> {
        let usage = RuntimeKeyUsage::JwtAccessTokenSigning;
        let keys = keys
            .active_key(usage)
            .into_iter()
            .chain(keys.retiring_keys(usage))
            .map(managed_jwt_verification_key)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            keys,
            now: access_verification_time,
        })
    }
}

fn access_verification_time() -> Result<i64, KeyManagerError> {
    crate::util::now_unix_epoch_secs_i64().map_err(|_| KeyManagerError::OperationFailed)
}

impl AccessTokenVerifier for ManagedAccessTokenVerifier {
    fn verify_access_token_signature(
        &self,
        kid: &str,
        alg: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, KeyManagerError> {
        let now = (self.now)()?;
        self.keys
            .iter()
            .find(|key| key.matches(kid, alg, now))
            .map_or(Ok(false), |key| key.verify(message, signature))
    }
}

#[cfg(test)]
mod tests;

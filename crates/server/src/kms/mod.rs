#[cfg(all(feature = "kms-aws", test))]
mod legacy_aws_evidence;
#[cfg(all(feature = "kms-aws", test))]
pub use self::legacy_aws_evidence::LegacyAwsKmsKeyManager;
#[cfg(test)]
mod in_memory;
#[cfg(test)]
pub use in_memory::{InMemoryKeyManager, InMemoryPublicJwtKeyManager};
mod managed;
pub use managed::ManagedJwtKeyManager;

/// Errors that can occur during key management operations.
#[derive(Debug)]
pub enum KeyManagerError {
    /// No key material available for the operation.
    KeyNotFound,
    /// Key material has been revoked and cannot be used.
    KeyRevoked,
    /// Catch-all for other failures.
    OperationFailed,
}

impl std::fmt::Display for KeyManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyNotFound => write!(f, "key not found"),
            Self::KeyRevoked => write!(f, "key revoked"),
            Self::OperationFailed => write!(f, "operation failed"),
        }
    }
}

impl std::error::Error for KeyManagerError {}

/// Simple key manager trait abstracting signing operations.
pub trait KeyManager: Send + Sync {
    /// Sign the provided message, returning raw signature bytes for the manager's JWT algorithm.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails or no active key is available.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, KeyManagerError>;
    /// Verify the provided signature against the message.
    ///
    /// # Errors
    ///
    /// Returns an error if verification cannot be performed because key material
    /// is unavailable.
    fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<bool, KeyManagerError>;
    /// Identifier for the current key material.
    fn key_id(&self) -> String;

    /// JWT signing algorithm implemented by [`Self::sign`] and [`Self::verify`].
    fn jwt_signing_alg(&self) -> &'static str;

    /// Public JWK corresponding to the JWT signing key, when resource servers can verify it.
    ///
    /// Symmetric managers intentionally return `None`: publishing HS* verification material would
    /// disclose the signing secret.
    fn jwt_signing_public_jwk(&self) -> Option<serde_json::Value> {
        None
    }

    /// Public JWKs accepted for JWT verification, including retiring keys when applicable.
    fn jwt_signing_public_jwks(&self) -> Vec<serde_json::Value> {
        self.jwt_signing_public_jwk().into_iter().collect()
    }

    /// Verify a JWT signature for the supplied JOSE `kid` and `alg`.
    ///
    /// Implementations with key rotation should override this method to allow
    /// retiring verification keys while keeping signing bound to the active key.
    fn verify_jwt_signature(
        &self,
        kid: &str,
        alg: &str,
        msg: &[u8],
        sig: &[u8],
    ) -> Result<bool, KeyManagerError> {
        if alg != self.jwt_signing_alg() || kid != self.key_id() {
            return Ok(false);
        }
        self.verify(msg, sig)
    }

    /// Rotate to a new key version.
    ///
    /// # Errors
    ///
    /// Returns an error if the manager cannot generate or persist a new key.
    fn rotate(&self) -> Result<(), KeyManagerError>;
    /// Revoke the current key material.
    ///
    /// # Errors
    ///
    /// Returns an error if the revocation operation cannot be completed.
    fn revoke(&self) -> Result<(), KeyManagerError>;

    #[cfg(test)]
    fn sign_federation(&self, _msg: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        Err(KeyManagerError::OperationFailed)
    }

    #[cfg(test)]
    fn federation_public_jwk(&self) -> Option<serde_json::Value> {
        None
    }

    #[cfg(test)]
    fn federation_alg(&self) -> &'static str {
        "ES256"
    }
}

#[cfg(test)]
/// Test-only capability retained for OpenID Federation structural evidence.
pub trait FederationKeyManager: Send + Sync {
    /// Sign a federation JWS signing input.
    ///
    /// # Errors
    ///
    /// Returns an error if signing is unsupported or key material is unavailable.
    fn sign_federation(&self, msg: &[u8]) -> Result<Vec<u8>, KeyManagerError>;

    /// Return the federation signing public JWK.
    fn federation_public_jwk(&self) -> Option<serde_json::Value>;

    /// Algorithm identifier for federation signing.
    fn federation_alg(&self) -> &'static str {
        "ES256"
    }
}

#[cfg(test)]
impl<T> FederationKeyManager for T
where
    T: KeyManager + ?Sized,
{
    fn sign_federation(&self, msg: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        KeyManager::sign_federation(self, msg)
    }

    fn federation_public_jwk(&self) -> Option<serde_json::Value> {
        KeyManager::federation_public_jwk(self)
    }

    fn federation_alg(&self) -> &'static str {
        KeyManager::federation_alg(self)
    }
}

#[cfg(test)]
pub(super) fn log_key_manager_invariant(error: impl std::fmt::Display, context: &'static str) {
    tracing::error!(error = %error, "{context}");
}

#[cfg(test)]
mod tests;

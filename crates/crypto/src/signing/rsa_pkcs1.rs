//! Imported RSA PKCS#1 v1.5 SHA-256 signing through the unified provider boundary.

use ring::signature::KeyPair as _;

use crate::error::CryptoError;

/// RSA PKCS#1 v1.5 SHA-256 signer owning an explicitly imported private key.
///
/// Admission uses ring's 2048..4096-bit private-key domain. This wrapper does not
/// establish formal assurance of the backend or its operational preconditions.
pub struct RsaPkcs1Sha256Signer(ring::signature::RsaKeyPair);

impl RsaPkcs1Sha256Signer {
    /// Import a PKCS#8 key without generating or substituting key material.
    ///
    /// # Errors
    /// Returns `CryptoError::InvalidKey` if the provider refuses the private key.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, CryptoError> {
        ring::signature::RsaKeyPair::from_pkcs8(der)
            .map(Self)
            .map_err(|_| CryptoError::InvalidKey("invalid PKCS#8 RSA signing key".into()))
    }

    /// Sign the supplied message with RSA PKCS#1 v1.5 and SHA-256.
    ///
    /// # Errors
    /// Returns `CryptoError::SigningFailed` if signing or provider randomness fails.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut signature = vec![0; self.0.public().modulus_len()];
        self.0
            .sign(
                &ring::signature::RSA_PKCS1_SHA256,
                &ring::rand::SystemRandom::new(),
                message,
                &mut signature,
            )
            .map_err(|_| CryptoError::SigningFailed("RSA PKCS#1 signing failed".into()))?;
        Ok(signature)
    }

    /// Return the imported key's public PKCS#1 DER representation.
    #[must_use]
    pub fn public_key_der(&self) -> &[u8] {
        self.0.public_key().as_ref()
    }
}

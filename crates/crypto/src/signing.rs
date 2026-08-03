//! Signing key operations (ECDSA P-256, Ed25519, RSA-PSS).
//!
//! Centralizes `ring::signature` and `aws_lc_rs::signature` usage.

use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

use crate::error::CryptoError;

/// ECDSA P-256 signing key.
pub struct EcdsaP256SigningKey {
    pkcs8: Vec<u8>,
}

/// Generated ECDSA P-256 key data.
pub struct EcdsaP256KeyData {
    /// PKCS#8 DER-encoded private key.
    pub pkcs8: Vec<u8>,
    /// Raw X coordinate (32 bytes).
    pub public_x: Vec<u8>,
    /// Raw Y coordinate (32 bytes).
    pub public_y: Vec<u8>,
}

impl EcdsaP256SigningKey {
    /// Generate a new ECDSA P-256 signing key.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::SigningFailed` if key generation or key parsing fails.
    pub fn generate() -> Result<EcdsaP256KeyData, CryptoError> {
        let rng = SystemRandom::new();
        let pkcs8_doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| CryptoError::SigningFailed("key generation failed".into()))?;
        let pkcs8 = pkcs8_doc.as_ref().to_vec();

        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8, &rng)
            .map_err(|_| CryptoError::SigningFailed("key parse failed".into()))?;

        let pub_bytes = key_pair.public_key().as_ref();
        if pub_bytes.len() != 65 || pub_bytes[0] != 0x04 {
            return Err(CryptoError::SigningFailed(
                "unexpected ECDSA public key encoding".into(),
            ));
        }
        let public_x = pub_bytes[1..33].to_vec();
        let public_y = pub_bytes[33..65].to_vec();

        Ok(EcdsaP256KeyData {
            pkcs8,
            public_x,
            public_y,
        })
    }

    /// Create a signing key from a PKCS#8 DER-encoded private key.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKey` when the PKCS#8 payload is malformed.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, CryptoError> {
        let rng = SystemRandom::new();
        // Validate the key parses correctly
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, &rng)
            .map_err(|_| CryptoError::InvalidKey("invalid PKCS#8 ECDSA key".into()))?;
        Ok(Self {
            pkcs8: pkcs8.to_vec(),
        })
    }

    /// Sign a message, returning the fixed-length R||S signature (64 bytes).
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::SigningFailed` if key parsing or signing fails.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let rng = SystemRandom::new();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &self.pkcs8, &rng)
                .map_err(|_| CryptoError::SigningFailed("key parse failed".into()))?;
        let sig = key_pair
            .sign(&rng, message)
            .map_err(|_| CryptoError::SigningFailed("signing operation failed".into()))?;
        Ok(sig.as_ref().to_vec())
    }

    /// Return the uncompressed SEC1 public key, encoded as `0x04 || X || Y`.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKey` when the stored PKCS#8 key cannot be parsed.
    pub fn public_key_sec1(&self) -> Result<Vec<u8>, CryptoError> {
        let rng = SystemRandom::new();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &self.pkcs8, &rng)
                .map_err(|_| CryptoError::InvalidKey("invalid PKCS#8 ECDSA key".into()))?;
        Ok(key_pair.public_key().as_ref().to_vec())
    }
}

/// Generated Ed25519 key data.
pub struct Ed25519KeyData {
    /// PKCS#8 DER-encoded private key.
    pub pkcs8: Vec<u8>,
    /// Raw public key bytes (32 bytes).
    pub public_key: Vec<u8>,
}

/// Ed25519 signing key.
pub struct Ed25519SigningKey {
    pkcs8: Vec<u8>,
}

impl Ed25519SigningKey {
    /// Generate a new Ed25519 signing key.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::SigningFailed` if key generation or key parsing fails.
    pub fn generate() -> Result<Ed25519KeyData, CryptoError> {
        let rng = SystemRandom::new();
        let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| CryptoError::SigningFailed("Ed25519 key generation failed".into()))?;
        let pkcs8 = pkcs8_doc.as_ref().to_vec();

        let key_pair = Ed25519KeyPair::from_pkcs8(&pkcs8)
            .map_err(|_| CryptoError::SigningFailed("Ed25519 key parse failed".into()))?;

        let public_key = key_pair.public_key().as_ref().to_vec();

        Ok(Ed25519KeyData { pkcs8, public_key })
    }

    /// Create a signing key from a PKCS#8 DER-encoded private key.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKey` when the PKCS#8 payload is malformed.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, CryptoError> {
        Ed25519KeyPair::from_pkcs8(pkcs8)
            .map_err(|_| CryptoError::InvalidKey("invalid PKCS#8 Ed25519 key".into()))?;
        Ok(Self {
            pkcs8: pkcs8.to_vec(),
        })
    }

    /// Sign a message, returning the Ed25519 signature (64 bytes).
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::SigningFailed` if key parsing fails.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let key_pair = Ed25519KeyPair::from_pkcs8(&self.pkcs8)
            .map_err(|_| CryptoError::SigningFailed("Ed25519 key parse failed".into()))?;
        let sig = key_pair.sign(message);
        Ok(sig.as_ref().to_vec())
    }

    /// Return the raw Ed25519 public key bytes.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKey` when the stored PKCS#8 key cannot be parsed.
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let key_pair = Ed25519KeyPair::from_pkcs8(&self.pkcs8)
            .map_err(|_| CryptoError::InvalidKey("invalid PKCS#8 Ed25519 key".into()))?;
        Ok(key_pair.public_key().as_ref().to_vec())
    }
}

/// RSA-PSS signing key (aws-lc-rs).
pub struct RsaPssSigner {
    key_pair: aws_lc_rs::signature::RsaKeyPair,
}

impl RsaPssSigner {
    /// Create from PKCS#8 DER bytes.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKey` when the RSA private key cannot be parsed.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, CryptoError> {
        let key_pair = aws_lc_rs::signature::RsaKeyPair::from_pkcs8(der)
            .or_else(|_| aws_lc_rs::signature::RsaKeyPair::from_der(der))
            .map_err(|e| CryptoError::InvalidKey(format!("RSA key parse failed: {e:?}")))?;
        Ok(Self { key_pair })
    }

    /// Sign with RSA-PSS SHA-256.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::SigningFailed` if the backend signing operation fails.
    pub fn sign_pss256(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut signature = vec![0; self.key_pair.public_modulus_len()];
        let rng = aws_lc_rs::rand::SystemRandom::new();
        self.key_pair
            .sign(
                &aws_lc_rs::signature::RSA_PSS_SHA256,
                &rng,
                message,
                &mut signature,
            )
            .map_err(|e| CryptoError::SigningFailed(format!("{e:?}")))?;
        Ok(signature)
    }

    /// Sign with RSA-PSS SHA-384.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::SigningFailed` if the backend signing operation fails.
    pub fn sign_pss384(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut signature = vec![0; self.key_pair.public_modulus_len()];
        let rng = aws_lc_rs::rand::SystemRandom::new();
        self.key_pair
            .sign(
                &aws_lc_rs::signature::RSA_PSS_SHA384,
                &rng,
                message,
                &mut signature,
            )
            .map_err(|e| CryptoError::SigningFailed(format!("{e:?}")))?;
        Ok(signature)
    }

    /// Sign with RSA-PSS SHA-512.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::SigningFailed` if the backend signing operation fails.
    pub fn sign_pss512(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut signature = vec![0; self.key_pair.public_modulus_len()];
        let rng = aws_lc_rs::rand::SystemRandom::new();
        self.key_pair
            .sign(
                &aws_lc_rs::signature::RSA_PSS_SHA512,
                &rng,
                message,
                &mut signature,
            )
            .map_err(|e| CryptoError::SigningFailed(format!("{e:?}")))?;
        Ok(signature)
    }

    /// Public key in DER format.
    #[must_use]
    pub fn public_key_der(&self) -> Vec<u8> {
        use aws_lc_rs::signature::KeyPair;
        self.key_pair.public_key().as_ref().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_sign() {
        let key_data_result = EcdsaP256SigningKey::generate();
        assert!(key_data_result.is_ok());
        let key_data = key_data_result.unwrap_or(EcdsaP256KeyData {
            pkcs8: Vec::new(),
            public_x: Vec::new(),
            public_y: Vec::new(),
        });
        let signer_result = EcdsaP256SigningKey::from_pkcs8(&key_data.pkcs8);
        assert!(signer_result.is_ok());
        let signer = signer_result.unwrap_or(EcdsaP256SigningKey { pkcs8: Vec::new() });
        let sig_result = signer.sign(b"test message");
        assert!(sig_result.is_ok());
        let sig = sig_result.unwrap_or_default();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn different_signatures_for_same_message() {
        let key_data_result = EcdsaP256SigningKey::generate();
        assert!(key_data_result.is_ok());
        let key_data = key_data_result.unwrap_or(EcdsaP256KeyData {
            pkcs8: Vec::new(),
            public_x: Vec::new(),
            public_y: Vec::new(),
        });
        let signer_result = EcdsaP256SigningKey::from_pkcs8(&key_data.pkcs8);
        assert!(signer_result.is_ok());
        let signer = signer_result.unwrap_or(EcdsaP256SigningKey { pkcs8: Vec::new() });
        let sig1_result = signer.sign(b"msg");
        let sig2_result = signer.sign(b"msg");
        assert!(sig1_result.is_ok());
        assert!(sig2_result.is_ok());
        let sig1 = sig1_result.unwrap_or_default();
        let sig2 = sig2_result.unwrap_or_default();
        assert_ne!(sig1, sig2, "ECDSA should use random nonce");
    }
}

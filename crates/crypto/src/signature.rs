//! Signature verification operations.
//!
//! Centralizes `aws_lc_rs::signature` and `p256` verification calls.

use aws_lc_rs::signature::{self, UnparsedPublicKey};
use p256::ecdsa::{signature::Verifier as _, Signature as P256Signature, VerifyingKey};

use crate::error::CryptoError;

/// Verify an Ed25519 signature given raw public-key bytes.
///
/// # Errors
///
/// Returns `CryptoError::VerificationFailed` when the public key or signature is invalid.
pub fn verify_ed25519(public_key: &[u8], message: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
        .verify(message, sig)
        .map_err(|_| CryptoError::VerificationFailed)
}

/// Verify an RSA-PSS SHA-256 signature given an SPKI-encoded public key.
///
/// # Errors
///
/// Returns `CryptoError::VerificationFailed` when the public key or signature is invalid.
pub fn verify_rsa_pss_sha256(spki: &[u8], message: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
    UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA256, spki)
        .verify(message, sig)
        .map_err(|_| CryptoError::VerificationFailed)
}

/// Verify an RSA PKCS#1 v1.5 SHA-256 signature given an SPKI-encoded public key.
///
/// # Errors
///
/// Returns `CryptoError::VerificationFailed` when the public key or signature is invalid.
pub fn verify_rsa_pkcs1_sha256(spki: &[u8], message: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
    UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, spki)
        .verify(message, sig)
        .map_err(|_| CryptoError::VerificationFailed)
}

/// Verify an ECDSA P-256 SHA-256 signature given an uncompressed SEC1 public key.
///
/// The `sec1` key must be 65 bytes: `0x04 || X(32) || Y(32)`.
///
/// # Errors
///
/// Returns `CryptoError::InvalidKey` when the public key is malformed and
/// `CryptoError::VerificationFailed` when signature verification fails.
pub fn verify_ecdsa_p256_sha256(
    sec1: &[u8],
    message: &[u8],
    sig: &[u8],
) -> Result<(), CryptoError> {
    let verifying_key = VerifyingKey::from_sec1_bytes(sec1)
        .map_err(|_| CryptoError::InvalidKey("invalid P-256 public key".into()))?;
    let signature = P256Signature::from_slice(sig).map_err(|_| CryptoError::VerificationFailed)?;
    verifying_key
        .verify(message, &signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

/// Verify an ECDSA P-256 SHA-256 fixed-length signature via `ring`.
///
/// Used for verifying federation signatures (R||S 64-byte format).
///
/// # Errors
///
/// Returns `CryptoError::VerificationFailed` when the public key or signature is invalid.
pub fn verify_ecdsa_p256_fixed(
    public_key: &[u8],
    message: &[u8],
    sig: &[u8],
) -> Result<(), CryptoError> {
    UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, public_key)
        .verify(message, sig)
        .map_err(|_| CryptoError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_ecdsa_p256_rejects_invalid_key() {
        let bad_key = vec![0x04; 10]; // too short
        assert!(matches!(
            verify_ecdsa_p256_sha256(&bad_key, b"msg", b"sig"),
            Err(CryptoError::InvalidKey(_))
        ));
    }

    #[test]
    fn verify_rsa_pss_rejects_bad_sig() {
        // Empty SPKI should fail
        assert!(matches!(
            verify_rsa_pss_sha256(b"not-spki", b"msg", b"sig"),
            Err(CryptoError::VerificationFailed)
        ));
    }
}

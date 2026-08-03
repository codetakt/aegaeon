//! Cryptographically secure random number generation.
//!
//! Token, nonce, and identifier generation is routed through the HMAC-SHA256
//! DRBG (`crate::drbg::drbg_random_bytes`), which combines OS entropy
//! (via `getrandom`) with the verified DRBG construction.
//!
//! **Scope:** This module covers token/nonce/identifier generation only.
//! Signing key generation and ECDSA/RSA-PSS nonce generation remain on
//! `ring::rand::SystemRandom` / `aws_lc_rs::rand::SystemRandom` in
//! `crate::signing` (Phase 3B/HACL* scope, not Phase C/RNG boundary).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use crate::error::CryptoError;

/// Fill a mutable byte slice with cryptographically secure random bytes.
///
/// Delegates to HMAC-SHA256 DRBG backed by OS entropy.
/// Handles buffers larger than the DRBG limit (65536) by chunking.
///
/// # Errors
///
/// Returns `CryptoError` when the underlying randomness provider fails.
pub fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError> {
    if buf.is_empty() {
        return Ok(());
    }
    // DRBG max is 65536 bytes per request; chunk for larger buffers
    for chunk in buf.chunks_mut(crate::drbg::MAX_BYTES_PER_REQUEST) {
        let output = crate::drbg::drbg_random_bytes(chunk.len());
        chunk.copy_from_slice(&output);
    }
    Ok(())
}

/// Generate `len` cryptographically secure random bytes.
///
/// Delegates to HMAC-SHA256 DRBG backed by OS entropy.
/// Handles lengths larger than the DRBG limit (65536) by chunking.
///
/// Note: The F* spec (`Random.fst`) requires `len > 0`. The `len == 0`
/// guard here is a Rust-only defensive measure outside the verified boundary;
/// no caller passes 0 in practice.
#[must_use]
pub fn random_bytes(len: usize) -> Vec<u8> {
    if len == 0 {
        return Vec::new();
    }
    if len <= crate::drbg::MAX_BYTES_PER_REQUEST {
        return crate::drbg::drbg_random_bytes(len);
    }
    // Chunk for large requests
    let mut result = Vec::with_capacity(len);
    let mut remaining = len;
    while remaining > 0 {
        let chunk_size = remaining.min(crate::drbg::MAX_BYTES_PER_REQUEST);
        result.extend_from_slice(&crate::drbg::drbg_random_bytes(chunk_size));
        remaining -= chunk_size;
    }
    result
}

/// Generate `byte_len` random bytes and return as base64url (no padding).
#[must_use]
pub fn random_base64url(byte_len: usize) -> String {
    let bytes = random_bytes(byte_len);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate a 32-byte random nonce.
///
/// Delegates to HMAC-SHA256 DRBG backed by OS entropy.
#[must_use]
pub fn ring_random_nonce_32() -> [u8; 32] {
    let output = crate::drbg::drbg_random_bytes(32);
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&output);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes_length() {
        assert_eq!(random_bytes(16).len(), 16);
        assert_eq!(random_bytes(32).len(), 32);
    }

    #[test]
    fn random_bytes_not_all_zero() {
        let bytes = random_bytes(32);
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn random_base64url_length() {
        let s = random_base64url(32);
        assert_eq!(s.len(), 43); // ceil(32 * 4/3) = 43 without padding
    }

    #[test]
    fn fill_random_works() {
        let mut buf = [0u8; 16];
        assert!(fill_random(&mut buf).is_ok());
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn random_bytes_zero_returns_empty() {
        assert!(random_bytes(0).is_empty());
    }

    #[test]
    fn fill_random_empty_is_ok() {
        assert!(fill_random(&mut []).is_ok());
    }
}

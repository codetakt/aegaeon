//! SHA-2 hash operations.
//!
//! Centralizes all `sha2` crate usage into this module.

use sha2::{Digest, Sha256, Sha384, Sha512};

/// Compute SHA-256 digest, returning a 32-byte array.
#[must_use]
pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute SHA-384 digest, returning a 48-byte array.
#[must_use]
pub fn sha384_digest(data: &[u8]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute SHA-512 digest, returning a 64-byte array.
#[must_use]
pub fn sha512_digest(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute SHA-256 and return as hex string.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = sha256_digest(data);
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Incremental SHA-256 hasher for multi-part inputs.
pub struct Sha256Hasher {
    inner: Sha256,
}

impl Sha256Hasher {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    #[must_use]
    pub fn finalize(self) -> [u8; 32] {
        self.inner.finalize().into()
    }
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_empty() {
        let expected: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(sha256_digest(b""), expected);
    }

    #[test]
    fn sha256_hex_output() {
        let hex = sha256_hex(b"test");
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn incremental_matches_oneshot() {
        let data = b"hello world";
        let oneshot = sha256_digest(data);
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"hello ");
        hasher.update(b"world");
        assert_eq!(hasher.finalize(), oneshot);
    }
}

//! HMAC-SHA256 operations.
//!
//! Centralizes `hmac` crate usage.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// HMAC-SHA256 key for signing and verification.
pub struct HmacSha256Key {
    key: Vec<u8>,
}

impl HmacSha256Key {
    /// Create a new HMAC key from raw bytes.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    /// Compute HMAC-SHA256 tag, returning 32 raw bytes.
    ///
    /// # Panics
    ///
    /// Panics only if the HMAC backend unexpectedly rejects the key length.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC can take key of any size");
        mac.update(message);
        mac.finalize().into_bytes().to_vec()
    }

    /// Verify an HMAC-SHA256 tag.
    ///
    /// # Panics
    ///
    /// Panics only if the HMAC backend unexpectedly rejects the key length.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn verify(&self, message: &[u8], tag: &[u8]) -> bool {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC can take key of any size");
        mac.update(message);
        mac.verify_slice(tag).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let key = HmacSha256Key::new(b"secret-key");
        let tag = key.sign(b"message");
        assert_eq!(tag.len(), 32);
        assert!(key.verify(b"message", &tag));
    }

    #[test]
    fn verify_rejects_bad_tag() {
        let key = HmacSha256Key::new(b"secret-key");
        assert!(!key.verify(b"message", b"bad-tag"));
    }
}

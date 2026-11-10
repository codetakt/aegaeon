//! HMAC-SHA256 operations.
//!
//! Centralizes `hmac` crate usage.

use hmac::{digest::FixedOutput, Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

/// HMAC-SHA256 key for signing and verification.
pub struct HmacSha256Key {
    key: Zeroizing<Vec<u8>>,
}

impl HmacSha256Key {
    /// Create a new HMAC key from raw bytes.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        let mut owned = Zeroizing::new(Vec::with_capacity(key.len()));
        owned.extend_from_slice(key);
        Self { key: owned }
    }

    /// Compute HMAC-SHA256 tag, returning 32 raw bytes.
    ///
    /// # Panics
    ///
    /// Panics only if the HMAC backend unexpectedly rejects the key length.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut output = self.sign_guarded(message);
        // This public API transfers the output allocation to its caller.
        std::mem::take(&mut *output)
    }

    // DRBG output is secret material. Allocate its guard before the provider
    // writes it, rather than copying an unguarded returned tag into a Vec.
    // Provider-internal HMAC/SHA state is outside this owned-buffer contract.
    #[allow(clippy::expect_used)]
    pub(crate) fn sign_guarded(&self, message: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC can take key of any size");
        mac.update(message);
        let mut output = Zeroizing::new(vec![0u8; 32]);
        FixedOutput::finalize_into(mac, output.as_mut_slice().into());
        output
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

    #[test]
    fn guarded_output_and_public_transfer_match_rfc4231() {
        let key = HmacSha256Key::new(&[0x0b; 20]);
        let guarded = key.sign_guarded(b"Hi There");
        let expected = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(guarded.as_slice(), expected);
        assert_eq!(key.sign(b"Hi There"), expected);
        assert!(key.verify(b"Hi There", &guarded));
    }
}

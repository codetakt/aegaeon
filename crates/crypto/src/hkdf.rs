//! RFC 5869 HKDF-SHA-256 for fixed 256-bit application subkeys.
use aws_lc_rs::hkdf::{Salt, HKDF_SHA256};
use zeroize::Zeroizing;

use crate::CryptoError;

/// Extract and expand a 32-byte key, binding the caller's context in `info`.
///
/// The returned buffer is erased on drop. This does not cover provider-internal
/// copies or the caller's input material. Salt and info are not secrets.
///
/// # Errors
///
/// Returns `CryptoError::InvalidKey` if the provider rejects key expansion.
pub fn derive_sha256_32(
    input: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let prk = Salt::new(HKDF_SHA256, salt).extract(input);
    let mut key = Zeroizing::new([0; 32]);
    prk.expand(&[info], HKDF_SHA256)
        .map_err(|_| CryptoError::InvalidKey("HKDF expansion failed".into()))?
        .fill(key.as_mut())
        .map_err(|_| CryptoError::InvalidKey("HKDF output failed".into()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc5869_sha256_vectors_first_32_bytes() -> Result<(), CryptoError> {
        // RFC 5869 Appendix A.1 and A.3. HKDF output is prefix-consistent;
        // this fixed-size API takes the first 32 bytes of each 42-byte vector.
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        assert_eq!(
            *derive_sha256_32(&[0x0b; 22], &salt, &info)?,
            [
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf,
            ]
        );
        assert_eq!(
            *derive_sha256_32(&[0x0b; 22], &[], &[])?,
            [
                0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c,
                0x5a, 0x31, 0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f,
                0x3c, 0x73, 0x8d, 0x2d,
            ]
        );
        Ok(())
    }
}

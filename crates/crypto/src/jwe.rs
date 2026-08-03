//! JWE decryption operations (RSA-OAEP + AES-256-GCM).
//!
//! Centralizes `aws_lc_rs::aead` and `aws_lc_rs::rsa` usage.

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use aws_lc_rs::rsa::{OaepPrivateDecryptingKey, PrivateDecryptingKey, OAEP_SHA1_MGF1SHA1};

use crate::error::CryptoError;

/// Unwrap a CEK using RSA-OAEP (SHA-1/MGF1).
///
/// # Errors
///
/// Returns `CryptoError::InvalidKey` when the private key cannot be parsed and
/// `CryptoError::DecryptionFailed` when RSA-OAEP unwrap fails.
pub fn rsa_oaep_unwrap(
    pkcs8_private_key: &[u8],
    encrypted_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let priv_key = PrivateDecryptingKey::from_pkcs8(pkcs8_private_key)
        .map_err(|_| CryptoError::InvalidKey("invalid RSA private key".into()))?;
    let oaep = OaepPrivateDecryptingKey::new(priv_key)
        .map_err(|_| CryptoError::InvalidKey("invalid RSA private key".into()))?;
    let mut buffer = vec![0u8; oaep.min_output_size()];
    oaep.decrypt(&OAEP_SHA1_MGF1SHA1, encrypted_key, &mut buffer, None)
        .map(|cek| cek.to_vec())
        .map_err(|_| CryptoError::DecryptionFailed("RSA-OAEP key unwrap failed".into()))
}

/// Decrypt AES-256-GCM ciphertext.
///
/// `cek` must be exactly 32 bytes. `iv` must be 12 bytes. `tag` must be 16 bytes.
///
/// # Errors
///
/// Returns `CryptoError::InvalidKey` when the CEK length is invalid and
/// `CryptoError::DecryptionFailed` when the IV length or authentication check fails.
pub fn decrypt_a256gcm(
    cek: &mut [u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let unbound = UnboundKey::new(&AES_256_GCM, cek)
        .map_err(|_| CryptoError::InvalidKey("invalid CEK length".into()))?;
    let key = LessSafeKey::new(unbound);
    let nonce_bytes: [u8; 12] = iv
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed("invalid IV length".into()))?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = Vec::with_capacity(ciphertext.len() + tag.len());
    in_out.extend_from_slice(ciphertext);
    in_out.extend_from_slice(tag);
    let result = key.open_in_place(nonce, Aad::from(aad), &mut in_out);
    cek.fill(0);
    result
        .map(|plaintext| plaintext.to_vec())
        .map_err(|_| CryptoError::DecryptionFailed("AES-256-GCM decryption failed".into()))
}

/// Encrypt with AES-256-GCM.
///
/// Used in management API test helpers. `key` must be 32 bytes.
///
/// # Errors
///
/// Returns `CryptoError::InvalidKey` when the key length is invalid and
/// `CryptoError::DecryptionFailed` when encryption fails.
pub fn encrypt_a256gcm(
    key: &[u8],
    nonce_bytes: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let unbound = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| CryptoError::InvalidKey("invalid key length".into()))?;
    let less_safe_key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(*nonce_bytes);
    let mut in_out = plaintext.to_vec();
    less_safe_key
        .seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| CryptoError::DecryptionFailed("AES-256-GCM encryption failed".into()))?;
    Ok(in_out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"hello world";
        let aad = b"";

        let ciphertext_result = encrypt_a256gcm(&key, &nonce, plaintext, aad);
        assert!(ciphertext_result.is_ok());
        let ciphertext = ciphertext_result.unwrap_or_default();
        // ciphertext = encrypted + 16-byte tag
        assert!(ciphertext.len() > plaintext.len());

        let tag_start = ciphertext.len() - 16;
        let mut cek = key;
        let decrypted_result = decrypt_a256gcm(
            &mut cek,
            &nonce,
            &ciphertext[..tag_start],
            &ciphertext[tag_start..],
            aad,
        );
        assert!(decrypted_result.is_ok());
        let decrypted = decrypted_result.unwrap_or_default();
        assert_eq!(decrypted, plaintext);
    }
}

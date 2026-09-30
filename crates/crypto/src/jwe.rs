//! JWE decryption operations (RSA-OAEP + AES-256-GCM).
//!
//! Centralizes `aws_lc_rs::aead` and `aws_lc_rs::rsa` usage.

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use aws_lc_rs::rsa::{OaepPrivateDecryptingKey, PrivateDecryptingKey, OAEP_SHA1_MGF1SHA1};
use zeroize::{Zeroize, Zeroizing};

use crate::error::CryptoError;

// The borrowed key is consumed even when validation returns early. This guard
// covers this slice, not provider-internal copies or the caller's other copies.
struct ConsumedCek<'a>(&'a mut [u8]);

impl Drop for ConsumedCek<'_> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Unwrap a CEK using RSA-OAEP (SHA-1/MGF1).
///
/// The caller owns the returned CEK and its eventual erasure. The intermediate
/// output allocation is guarded until ownership transfers on success.
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
    let mut buffer = Zeroizing::new(vec![0u8; oaep.min_output_size()]);
    let cek_len = oaep
        .decrypt(&OAEP_SHA1_MGF1SHA1, encrypted_key, &mut buffer, None)
        .map_err(|_| CryptoError::DecryptionFailed("RSA-OAEP key unwrap failed".into()))?
        .len();
    // aws-lc-rs returns the initialized output prefix. Erase the unused tail
    // before truncation, then transfer this allocation instead of copying CEK.
    buffer[cek_len..].zeroize();
    buffer.truncate(cek_len);
    Ok(std::mem::take(&mut *buffer))
}

/// Decrypt AES-256-GCM ciphertext.
///
/// `cek` must be exactly 32 bytes. `iv` must be 12 bytes. `tag` must be exactly
/// 16 bytes, as required by [RFC 7518, Section 5.3]. Ciphertext and tag are
/// validated as separate inputs; moving bytes between them is rejected.
///
/// The supplied mutable CEK is consumed: its bytes are zeroized on every
/// ordinary return, including validation and authentication errors. The caller
/// owns the returned plaintext and its eventual erasure. Provider-internal
/// objects and other copies of the inputs are outside this buffer contract.
///
/// [RFC 7518, Section 5.3]: https://www.rfc-editor.org/rfc/rfc7518#section-5.3
///
/// # Errors
///
/// Returns `CryptoError::InvalidKey` when the CEK length is invalid and
/// `CryptoError::DecryptionFailed` when the IV/tag length or authentication check fails.
pub fn decrypt_a256gcm(
    cek: &mut [u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cek = ConsumedCek(cek);
    let unbound = UnboundKey::new(&AES_256_GCM, cek.0)
        .map_err(|_| CryptoError::InvalidKey("invalid CEK length".into()))?;
    let key = LessSafeKey::new(unbound);
    let nonce_bytes: [u8; 12] = iv
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed("invalid IV length".into()))?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    if tag.len() != 16 {
        return Err(CryptoError::DecryptionFailed("invalid tag length".into()));
    }
    let capacity = ciphertext
        .len()
        .checked_add(tag.len())
        .ok_or_else(|| CryptoError::DecryptionFailed("ciphertext too long".into()))?;
    let mut in_out = Zeroizing::new(Vec::with_capacity(capacity));
    in_out.extend_from_slice(ciphertext);
    in_out.extend_from_slice(tag);
    let plaintext_len = key
        .open_in_place(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| CryptoError::DecryptionFailed("AES-256-GCM decryption failed".into()))?
        .len();
    // open_in_place returns the plaintext prefix of this same allocation.
    in_out[plaintext_len..].zeroize();
    in_out.truncate(plaintext_len);
    Ok(std::mem::take(&mut *in_out))
}

/// Encrypt with AES-256-GCM.
///
/// `key` must be 32 bytes. The caller must supply a fresh nonce for each seal
/// under the same key, including uses in other domains. Borrowed key/plaintext
/// inputs remain caller-owned; the intermediate output allocation is guarded.
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
    let capacity = plaintext
        .len()
        .checked_add(16)
        .ok_or_else(|| CryptoError::DecryptionFailed("plaintext too long".into()))?;
    // Reserve the tag before copying plaintext so appending it cannot reallocate
    // a secret-bearing buffer. Provider-internal copies are outside this guard.
    let mut in_out = Zeroizing::new(Vec::with_capacity(capacity));
    in_out.extend_from_slice(plaintext);
    less_safe_key
        .seal_in_place_append_tag(nonce, Aad::from(aad), &mut *in_out)
        .map_err(|_| CryptoError::DecryptionFailed("AES-256-GCM encryption failed".into()))?;
    Ok(std::mem::take(&mut *in_out))
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

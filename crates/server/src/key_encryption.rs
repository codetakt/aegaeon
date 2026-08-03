use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use thiserror::Error;

pub const KEY_ENCRYPTION_KEY_ENV: &str = "AEGAEON_KEY_ENCRYPTION_KEY";
pub const KEY_HANDLE_ENVELOPE_PREFIX: &str = "aeg-runtime-key-handle-v1.";
const KEY_HANDLE_AAD_DOMAIN: &[u8] = b"aegaeon/runtime-key-handle/v1";
const KEY_HANDLE_MIN_ENVELOPE_BYTES: usize = 12 + 16;

#[derive(Debug, Clone, Copy)]
pub struct KeyHandleEncryptionContext<'a> {
    pub environment_id: uuid::Uuid,
    pub usage: &'a str,
    pub provider: &'a str,
    pub algorithm: &'a str,
    pub kid: &'a str,
}

impl<'a> KeyHandleEncryptionContext<'a> {
    #[must_use]
    pub const fn new(
        environment_id: uuid::Uuid,
        usage: &'a str,
        provider: &'a str,
        algorithm: &'a str,
        kid: &'a str,
    ) -> Self {
        Self {
            environment_id,
            usage,
            provider,
            algorithm,
            kid,
        }
    }

    fn aad(self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(
            KEY_HANDLE_AAD_DOMAIN.len()
                + self.environment_id.as_bytes().len()
                + self.usage.len()
                + self.provider.len()
                + self.algorithm.len()
                + self.kid.len()
                + (std::mem::size_of::<u64>() * 5),
        );
        aad.extend_from_slice(KEY_HANDLE_AAD_DOMAIN);
        append_aad_field(&mut aad, self.environment_id.as_bytes());
        append_aad_field(&mut aad, self.usage.as_bytes());
        append_aad_field(&mut aad, self.provider.as_bytes());
        append_aad_field(&mut aad, self.algorithm.as_bytes());
        append_aad_field(&mut aad, self.kid.as_bytes());
        aad
    }
}

fn append_aad_field(aad: &mut Vec<u8>, value: &[u8]) {
    aad.extend_from_slice(&(value.len() as u64).to_be_bytes());
    aad.extend_from_slice(value);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyEncryptionKeyLoadError {
    Missing,
    Empty,
    NonUnicode,
    InvalidEncoding,
    InvalidLength(usize),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum KeyHandleEncryptionError {
    #[error("failed to generate nonce")]
    NonceGeneration,

    #[error("AES-GCM encryption failed")]
    Encryption,

    #[error("invalid encrypted key handle envelope")]
    InvalidEnvelope,

    #[error("invalid base64 in encrypted key handle")]
    InvalidEncoding,

    #[error("encrypted key handle too short")]
    TooShort,

    #[error("invalid nonce length in encrypted key handle")]
    InvalidNonceLength,

    #[error("AES-GCM decryption failed")]
    Decryption,

    #[error("decrypted key handle is not valid UTF-8")]
    InvalidUtf8,
}

/// Load the key encryption key from `AEGAEON_KEY_ENCRYPTION_KEY` env var (base64-encoded 256-bit).
pub fn load_key_encryption_key() -> Result<[u8; 32], KeyEncryptionKeyLoadError> {
    let raw = match std::env::var(KEY_ENCRYPTION_KEY_ENV) {
        Ok(raw) => raw,
        Err(std::env::VarError::NotPresent) => return Err(KeyEncryptionKeyLoadError::Missing),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(KeyEncryptionKeyLoadError::NonUnicode)
        }
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(KeyEncryptionKeyLoadError::Empty);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(trimmed)
        .map_err(|_| KeyEncryptionKeyLoadError::InvalidEncoding)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| KeyEncryptionKeyLoadError::InvalidLength(bytes.len()))
}

#[must_use]
pub fn has_supported_key_handle_envelope(encrypted: &str) -> bool {
    encrypted
        .strip_prefix(KEY_HANDLE_ENVELOPE_PREFIX)
        .and_then(|encoded| URL_SAFE_NO_PAD.decode(encoded).ok())
        .is_some_and(|data| data.len() >= KEY_HANDLE_MIN_ENVELOPE_BYTES)
}

/// Encrypt a key handle with AES-256-GCM and runtime-key contextual AAD.
pub fn encrypt_key_handle(
    plaintext: &str,
    kek: &[u8; 32],
    context: KeyHandleEncryptionContext<'_>,
) -> Result<String, KeyHandleEncryptionError> {
    let mut nonce_bytes = [0u8; 12];
    aegaeon_crypto::rand::fill_random(&mut nonce_bytes)
        .map_err(|_| KeyHandleEncryptionError::NonceGeneration)?;

    let aad = context.aad();
    let ct_tag = aegaeon_crypto::jwe::encrypt_a256gcm(
        kek,
        &nonce_bytes,
        plaintext.as_bytes(),
        aad.as_slice(),
    )
    .map_err(|_| KeyHandleEncryptionError::Encryption)?;

    let mut result = Vec::with_capacity(12 + ct_tag.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ct_tag);

    Ok(format!(
        "{KEY_HANDLE_ENVELOPE_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(&result)
    ))
}

/// Decrypt a key handle that was encrypted with [`encrypt_key_handle`].
pub fn decrypt_key_handle(
    encrypted: &str,
    kek: &[u8; 32],
    context: KeyHandleEncryptionContext<'_>,
) -> Result<String, KeyHandleEncryptionError> {
    let encoded = encrypted
        .strip_prefix(KEY_HANDLE_ENVELOPE_PREFIX)
        .ok_or(KeyHandleEncryptionError::InvalidEnvelope)?;
    let data = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| KeyHandleEncryptionError::InvalidEncoding)?;
    if data.len() < KEY_HANDLE_MIN_ENVELOPE_BYTES {
        return Err(KeyHandleEncryptionError::TooShort);
    }

    let nonce: [u8; 12] = data[..12]
        .try_into()
        .map_err(|_| KeyHandleEncryptionError::InvalidNonceLength)?;
    let tag_start = data.len() - 16;
    let ciphertext = &data[12..tag_start];
    let tag = &data[tag_start..];

    let mut cek = *kek;
    let aad = context.aad();
    let plaintext_bytes =
        aegaeon_crypto::jwe::decrypt_a256gcm(&mut cek, &nonce, ciphertext, tag, aad.as_slice())
            .map_err(|_| KeyHandleEncryptionError::Decryption)?;

    String::from_utf8(plaintext_bytes).map_err(|_| KeyHandleEncryptionError::InvalidUtf8)
}

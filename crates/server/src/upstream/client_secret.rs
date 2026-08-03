use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use crate::key_encryption::{load_key_encryption_key, KeyEncryptionKeyLoadError};

#[cfg(test)]
pub(super) use crate::key_encryption::KEY_ENCRYPTION_KEY_ENV;

pub(super) const UPSTREAM_CLIENT_SECRET_ENVELOPE_PREFIX: &str = "aeg-upstream-client-secret-v1.";
const UPSTREAM_CLIENT_SECRET_AAD_DOMAIN: &[u8] = b"aegaeon/upstream-client-secret/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamClientSecretEnvelopeError {
    KeyMissing,
    KeyInvalid,
    NonceGenerationFailed,
    EncryptionFailed,
    EnvelopeInvalid,
    DecryptionFailed,
    PlaintextInvalid,
}

impl From<KeyEncryptionKeyLoadError> for UpstreamClientSecretEnvelopeError {
    fn from(error: KeyEncryptionKeyLoadError) -> Self {
        match error {
            KeyEncryptionKeyLoadError::Missing => Self::KeyMissing,
            KeyEncryptionKeyLoadError::Empty
            | KeyEncryptionKeyLoadError::NonUnicode
            | KeyEncryptionKeyLoadError::InvalidEncoding
            | KeyEncryptionKeyLoadError::InvalidLength(_) => Self::KeyInvalid,
        }
    }
}

#[must_use]
pub fn upstream_client_auth_method_uses_secret(method: &str) -> bool {
    matches!(
        method.trim().to_ascii_lowercase().as_str(),
        "client_secret_basic" | "client_secret_post"
    )
}

#[must_use]
pub fn upstream_client_auth_method_supported(method: &str) -> bool {
    matches!(
        method.trim().to_ascii_lowercase().as_str(),
        "client_secret_basic" | "client_secret_post" | "none"
    )
}

fn load_upstream_client_secret_envelope_key() -> Result<[u8; 32], UpstreamClientSecretEnvelopeError>
{
    load_key_encryption_key().map_err(Into::into)
}

fn upstream_client_secret_aad(environment_id: uuid::Uuid, connection_id: uuid::Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(UPSTREAM_CLIENT_SECRET_AAD_DOMAIN.len() + 34);
    aad.extend_from_slice(UPSTREAM_CLIENT_SECRET_AAD_DOMAIN);
    aad.push(0);
    aad.extend_from_slice(environment_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(connection_id.as_bytes());
    aad
}

pub fn seal_upstream_client_secret(
    client_secret: &str,
    environment_id: uuid::Uuid,
    connection_id: uuid::Uuid,
) -> Result<Vec<u8>, UpstreamClientSecretEnvelopeError> {
    let key = load_upstream_client_secret_envelope_key()?;
    let mut nonce = [0u8; 12];
    aegaeon_crypto::rand::fill_random(&mut nonce)
        .map_err(|_| UpstreamClientSecretEnvelopeError::NonceGenerationFailed)?;
    let aad = upstream_client_secret_aad(environment_id, connection_id);
    let ciphertext =
        aegaeon_crypto::jwe::encrypt_a256gcm(&key, &nonce, client_secret.as_bytes(), &aad)
            .map_err(|_| UpstreamClientSecretEnvelopeError::EncryptionFailed)?;
    let mut envelope = Vec::with_capacity(12 + ciphertext.len());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(format!(
        "{UPSTREAM_CLIENT_SECRET_ENVELOPE_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(envelope)
    )
    .into_bytes())
}

pub fn open_upstream_client_secret(
    encrypted_client_secret: &[u8],
    environment_id: uuid::Uuid,
    connection_id: uuid::Uuid,
) -> Result<String, UpstreamClientSecretEnvelopeError> {
    let key = load_upstream_client_secret_envelope_key()?;
    let envelope = std::str::from_utf8(encrypted_client_secret)
        .map_err(|_| UpstreamClientSecretEnvelopeError::EnvelopeInvalid)?;
    let encoded = envelope
        .strip_prefix(UPSTREAM_CLIENT_SECRET_ENVELOPE_PREFIX)
        .ok_or(UpstreamClientSecretEnvelopeError::EnvelopeInvalid)?;
    let sealed = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| UpstreamClientSecretEnvelopeError::EnvelopeInvalid)?;
    if sealed.len() <= 12 + 16 {
        return Err(UpstreamClientSecretEnvelopeError::EnvelopeInvalid);
    }
    let nonce: [u8; 12] = sealed[..12]
        .try_into()
        .map_err(|_| UpstreamClientSecretEnvelopeError::EnvelopeInvalid)?;
    let tag_start = sealed.len() - 16;
    let ciphertext = &sealed[12..tag_start];
    let tag = &sealed[tag_start..];
    let aad = upstream_client_secret_aad(environment_id, connection_id);
    let mut cek = key;
    let plaintext = aegaeon_crypto::jwe::decrypt_a256gcm(&mut cek, &nonce, ciphertext, tag, &aad)
        .map_err(|_| UpstreamClientSecretEnvelopeError::DecryptionFailed)?;
    String::from_utf8(plaintext).map_err(|_| UpstreamClientSecretEnvelopeError::PlaintextInvalid)
}

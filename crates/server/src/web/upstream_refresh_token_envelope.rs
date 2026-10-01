use super::oauth_errors::no_cache_json_error_with_iss as json_error_with_iss;
use serde::{Deserialize, Serialize};

mod context;
use axum::{http::StatusCode, response::Response};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
pub(super) use context::UpstreamRefreshAuthenticationContext;

use crate::key_encryption::{load_key_encryption_key, KeyEncryptionKeyLoadError};

#[cfg(test)]
use crate::key_encryption::KEY_ENCRYPTION_KEY_ENV;

const UPSTREAM_REFRESH_TOKEN_ENVELOPE_PREFIX_V2: &str = "aeg-upstream-refresh-token-v2.";
const UPSTREAM_REFRESH_TOKEN_ENVELOPE_PREFIX: &str = "aeg-upstream-refresh-token-v3.";
const MAX_GRANT_PLAINTEXT_BYTES: usize = super::UPSTREAM_MAX_BODY_BYTES * 2;
const MAX_ENVELOPE_BYTES: usize = ((MAX_GRANT_PLAINTEXT_BYTES + 28) * 4).div_ceil(3) + 64;
const UPSTREAM_REFRESH_TOKEN_AAD_DOMAIN_V3: &[u8] = b"aegaeon/upstream-refresh-token/v3";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UpstreamRefreshTokenEnvelopeError {
    KeyMissing,
    KeyInvalid,
    NonceGenerationFailed,
    EncryptionFailed,
    EnvelopeInvalid,
    DecryptionFailed,
    PlaintextInvalid,
    ContextInvalid,
    ReauthenticationRequired,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UpstreamRefreshGrant {
    pub(super) refresh_token: String,
    pub(super) original: UpstreamRefreshAuthenticationContext,
}

impl UpstreamRefreshGrant {
    fn validate(
        &self,
        issuer: &str,
        subject_hash: &str,
    ) -> Result<(), UpstreamRefreshTokenEnvelopeError> {
        if self.refresh_token.trim().is_empty()
            || self.refresh_token.len() > super::UPSTREAM_MAX_BODY_BYTES
        {
            return Err(UpstreamRefreshTokenEnvelopeError::PlaintextInvalid);
        }
        self.original.validate_binding(issuer, subject_hash)
    }
}

impl From<KeyEncryptionKeyLoadError> for UpstreamRefreshTokenEnvelopeError {
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

fn load_upstream_refresh_token_envelope_key() -> Result<[u8; 32], UpstreamRefreshTokenEnvelopeError>
{
    load_key_encryption_key().map_err(Into::into)
}

fn upstream_refresh_token_aad_v3(
    environment_id: uuid::Uuid,
    upstream_issuer: &str,
    upstream_sub_hash: &str,
    connection_id: uuid::Uuid,
    generation: i64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        UPSTREAM_REFRESH_TOKEN_AAD_DOMAIN_V3.len()
            + 16
            + upstream_issuer.len()
            + upstream_sub_hash.len()
            + 16
            + 8
            + 5,
    );
    aad.extend_from_slice(UPSTREAM_REFRESH_TOKEN_AAD_DOMAIN_V3);
    aad.push(0);
    aad.extend_from_slice(environment_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(upstream_issuer.as_bytes());
    aad.push(0);
    aad.extend_from_slice(upstream_sub_hash.as_bytes());
    aad.push(0);
    aad.extend_from_slice(connection_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(&generation.to_be_bytes());
    aad
}

fn decrypt_upstream_refresh_token_envelope(
    key: [u8; 32],
    encoded: &str,
    aad: &[u8],
) -> Result<String, UpstreamRefreshTokenEnvelopeError> {
    let sealed = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| UpstreamRefreshTokenEnvelopeError::EnvelopeInvalid)?;
    if sealed.len() <= 12 + 16 {
        return Err(UpstreamRefreshTokenEnvelopeError::EnvelopeInvalid);
    }
    let nonce: [u8; 12] = sealed[..12]
        .try_into()
        .map_err(|_| UpstreamRefreshTokenEnvelopeError::EnvelopeInvalid)?;
    let tag_start = sealed.len() - 16;
    let ciphertext = &sealed[12..tag_start];
    let tag = &sealed[tag_start..];
    let mut cek = key;
    let plaintext = aegaeon_crypto::jwe::decrypt_a256gcm(&mut cek, &nonce, ciphertext, tag, aad)
        .map_err(|_| UpstreamRefreshTokenEnvelopeError::DecryptionFailed)?;
    String::from_utf8(plaintext).map_err(|_| UpstreamRefreshTokenEnvelopeError::PlaintextInvalid)
}

pub(super) fn seal_upstream_refresh_token(
    refresh_token: &str,
    environment_id: uuid::Uuid,
    upstream_issuer: &str,
    upstream_sub_hash: &str,
    connection_id: uuid::Uuid,
    generation: i64,
    original: &UpstreamRefreshAuthenticationContext,
) -> Result<Vec<u8>, UpstreamRefreshTokenEnvelopeError> {
    if generation < 1 {
        return Err(UpstreamRefreshTokenEnvelopeError::ContextInvalid);
    }
    let grant = UpstreamRefreshGrant {
        refresh_token: refresh_token.to_string(),
        original: original.clone(),
    };
    grant.validate(upstream_issuer, upstream_sub_hash)?;
    let plaintext = serde_json::to_vec(&grant)
        .map_err(|_| UpstreamRefreshTokenEnvelopeError::PlaintextInvalid)?;
    if plaintext.len() > MAX_GRANT_PLAINTEXT_BYTES {
        return Err(UpstreamRefreshTokenEnvelopeError::PlaintextInvalid);
    }
    let key = load_upstream_refresh_token_envelope_key()?;
    let mut nonce = [0u8; 12];
    aegaeon_crypto::rand::fill_random(&mut nonce)
        .map_err(|_| UpstreamRefreshTokenEnvelopeError::NonceGenerationFailed)?;
    let aad = upstream_refresh_token_aad_v3(
        environment_id,
        upstream_issuer,
        upstream_sub_hash,
        connection_id,
        generation,
    );
    let ciphertext = aegaeon_crypto::jwe::encrypt_a256gcm(&key, &nonce, &plaintext, aad.as_slice())
        .map_err(|_| UpstreamRefreshTokenEnvelopeError::EncryptionFailed)?;
    let mut envelope = Vec::with_capacity(12 + ciphertext.len());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(ciphertext.as_slice());
    Ok(format!(
        "{UPSTREAM_REFRESH_TOKEN_ENVELOPE_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(envelope)
    )
    .into_bytes())
}

pub(super) fn open_upstream_refresh_token(
    encrypted_refresh_token: &[u8],
    environment_id: uuid::Uuid,
    upstream_issuer: &str,
    upstream_sub_hash: &str,
    connection_id: uuid::Uuid,
    generation: i64,
) -> Result<UpstreamRefreshGrant, UpstreamRefreshTokenEnvelopeError> {
    if encrypted_refresh_token.len() > MAX_ENVELOPE_BYTES || generation < 1 {
        return Err(UpstreamRefreshTokenEnvelopeError::EnvelopeInvalid);
    }
    let envelope = std::str::from_utf8(encrypted_refresh_token)
        .map_err(|_| UpstreamRefreshTokenEnvelopeError::EnvelopeInvalid)?;
    if envelope.starts_with(UPSTREAM_REFRESH_TOKEN_ENVELOPE_PREFIX_V2) {
        return Err(UpstreamRefreshTokenEnvelopeError::ReauthenticationRequired);
    }
    let Some(encoded) = envelope.strip_prefix(UPSTREAM_REFRESH_TOKEN_ENVELOPE_PREFIX) else {
        return Err(UpstreamRefreshTokenEnvelopeError::EnvelopeInvalid);
    };
    let aad = upstream_refresh_token_aad_v3(
        environment_id,
        upstream_issuer,
        upstream_sub_hash,
        connection_id,
        generation,
    );
    let key = load_upstream_refresh_token_envelope_key()?;
    let plaintext = decrypt_upstream_refresh_token_envelope(key, encoded, aad.as_slice())?;
    if plaintext.len() > MAX_GRANT_PLAINTEXT_BYTES {
        return Err(UpstreamRefreshTokenEnvelopeError::PlaintextInvalid);
    }
    let grant: UpstreamRefreshGrant = serde_json::from_str(&plaintext)
        .map_err(|_| UpstreamRefreshTokenEnvelopeError::PlaintextInvalid)?;
    grant.validate(upstream_issuer, upstream_sub_hash)?;
    Ok(grant)
}

pub(super) fn upstream_refresh_token_envelope_error_response(
    error: UpstreamRefreshTokenEnvelopeError,
    message: &'static str,
    issuer_base: &str,
) -> Response {
    if error == UpstreamRefreshTokenEnvelopeError::ReauthenticationRequired {
        return json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            Some("upstream reauthentication required"),
            issuer_base,
        );
    }
    tracing::warn!(?error, "upstream refresh token envelope operation failed");
    json_error_with_iss(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        Some(message),
        issuer_base,
    )
}

#[cfg(test)]
mod tests;

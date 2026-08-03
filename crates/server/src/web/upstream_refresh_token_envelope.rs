use super::oauth_errors::json_error_with_iss;
use axum::{http::StatusCode, response::Response};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use crate::key_encryption::{load_key_encryption_key, KeyEncryptionKeyLoadError};

#[cfg(test)]
use crate::key_encryption::KEY_ENCRYPTION_KEY_ENV;

const UPSTREAM_REFRESH_TOKEN_ENVELOPE_PREFIX_V2: &str = "aeg-upstream-refresh-token-v2.";
const UPSTREAM_REFRESH_TOKEN_ENVELOPE_PREFIX: &str = UPSTREAM_REFRESH_TOKEN_ENVELOPE_PREFIX_V2;
const UPSTREAM_REFRESH_TOKEN_AAD_DOMAIN_V2: &[u8] = b"aegaeon/upstream-refresh-token/v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UpstreamRefreshTokenEnvelopeError {
    KeyMissing,
    KeyInvalid,
    NonceGenerationFailed,
    EncryptionFailed,
    EnvelopeInvalid,
    DecryptionFailed,
    PlaintextInvalid,
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

fn upstream_refresh_token_aad_v2(
    environment_id: uuid::Uuid,
    upstream_issuer: &str,
    upstream_sub_hash: &str,
    connection_id: uuid::Uuid,
    generation: i64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        UPSTREAM_REFRESH_TOKEN_AAD_DOMAIN_V2.len()
            + 16
            + upstream_issuer.len()
            + upstream_sub_hash.len()
            + 16
            + 8
            + 5,
    );
    aad.extend_from_slice(UPSTREAM_REFRESH_TOKEN_AAD_DOMAIN_V2);
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
) -> Result<Vec<u8>, UpstreamRefreshTokenEnvelopeError> {
    let key = load_upstream_refresh_token_envelope_key()?;
    let mut nonce = [0u8; 12];
    aegaeon_crypto::rand::fill_random(&mut nonce)
        .map_err(|_| UpstreamRefreshTokenEnvelopeError::NonceGenerationFailed)?;
    let aad = upstream_refresh_token_aad_v2(
        environment_id,
        upstream_issuer,
        upstream_sub_hash,
        connection_id,
        generation,
    );
    let ciphertext = aegaeon_crypto::jwe::encrypt_a256gcm(
        &key,
        &nonce,
        refresh_token.as_bytes(),
        aad.as_slice(),
    )
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
) -> Result<String, UpstreamRefreshTokenEnvelopeError> {
    let key = load_upstream_refresh_token_envelope_key()?;
    let envelope = std::str::from_utf8(encrypted_refresh_token)
        .map_err(|_| UpstreamRefreshTokenEnvelopeError::EnvelopeInvalid)?;
    let Some(encoded) = envelope.strip_prefix(UPSTREAM_REFRESH_TOKEN_ENVELOPE_PREFIX_V2) else {
        return Err(UpstreamRefreshTokenEnvelopeError::EnvelopeInvalid);
    };
    let aad = upstream_refresh_token_aad_v2(
        environment_id,
        upstream_issuer,
        upstream_sub_hash,
        connection_id,
        generation,
    );
    decrypt_upstream_refresh_token_envelope(key, encoded, aad.as_slice())
}

pub(super) fn upstream_refresh_token_envelope_error_response(
    error: UpstreamRefreshTokenEnvelopeError,
    message: &'static str,
    issuer_base: &str,
) -> Response {
    tracing::warn!(?error, "upstream refresh token envelope operation failed");
    json_error_with_iss(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        Some(message),
        issuer_base,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), String>;

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn new(key: &'static str, value: Option<&str>) -> Self {
            let previous = std::env::var(key).ok();
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match self.previous.as_deref() {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    #[test]
    fn upstream_refresh_token_envelope_round_trips_without_plaintext() -> TestResult {
        let _guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
            .lock()
            .map_err(|_| "key encryption key env guard".to_string())?;
        let key = URL_SAFE_NO_PAD.encode([0x41u8; 32]);
        let _env = EnvVarGuard::new(KEY_ENCRYPTION_KEY_ENV, Some(key.as_str()));
        let environment_id = uuid::Uuid::new_v4();
        let connection_id = uuid::Uuid::new_v4();
        let issuer = "https://issuer.example";
        let upstream_sub_hash = "subject-hash";
        let refresh_token = "upstream-refresh-token-secret";

        let sealed = seal_upstream_refresh_token(
            refresh_token,
            environment_id,
            issuer,
            upstream_sub_hash,
            connection_id,
            1,
        )
        .map_err(|err| format!("seal refresh token: {err:?}"))?;
        let envelope = std::str::from_utf8(sealed.as_slice())
            .map_err(|err| format!("sealed envelope should be utf8: {err}"))?;

        assert!(envelope.starts_with(UPSTREAM_REFRESH_TOKEN_ENVELOPE_PREFIX));
        assert!(!envelope.contains(refresh_token));
        assert_eq!(
            open_upstream_refresh_token(
                sealed.as_slice(),
                environment_id,
                issuer,
                upstream_sub_hash,
                connection_id,
                1
            )
            .map_err(|err| format!("open refresh token: {err:?}"))?,
            refresh_token
        );
        Ok(())
    }

    #[test]
    fn upstream_refresh_token_envelope_rejects_plaintext_legacy_value() -> TestResult {
        let _guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
            .lock()
            .map_err(|_| "key encryption key env guard".to_string())?;
        let key = URL_SAFE_NO_PAD.encode([0x42u8; 32]);
        let _env = EnvVarGuard::new(KEY_ENCRYPTION_KEY_ENV, Some(key.as_str()));
        let err = open_upstream_refresh_token(
            b"legacy-plaintext-refresh-token",
            uuid::Uuid::new_v4(),
            "https://issuer.example",
            "subject-hash",
            uuid::Uuid::new_v4(),
            1,
        )
        .err()
        .ok_or_else(|| "legacy plaintext must fail closed".to_string())?;

        assert_eq!(err, UpstreamRefreshTokenEnvelopeError::EnvelopeInvalid);
        Ok(())
    }

    #[test]
    fn upstream_refresh_token_envelope_binds_context_as_aad() -> TestResult {
        let _guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
            .lock()
            .map_err(|_| "key encryption key env guard".to_string())?;
        let key = URL_SAFE_NO_PAD.encode([0x43u8; 32]);
        let _env = EnvVarGuard::new(KEY_ENCRYPTION_KEY_ENV, Some(key.as_str()));
        let environment_id = uuid::Uuid::new_v4();
        let connection_id = uuid::Uuid::new_v4();
        let sealed = seal_upstream_refresh_token(
            "upstream-refresh-token-secret",
            environment_id,
            "https://issuer.example",
            "subject-hash",
            connection_id,
            1,
        )
        .map_err(|err| format!("seal refresh token: {err:?}"))?;

        let err = open_upstream_refresh_token(
            sealed.as_slice(),
            environment_id,
            "https://issuer.example",
            "different-subject-hash",
            connection_id,
            1,
        )
        .err()
        .ok_or_else(|| "AAD mismatch must fail closed".to_string())?;

        assert_eq!(err, UpstreamRefreshTokenEnvelopeError::DecryptionFailed);
        Ok(())
    }

    #[test]
    fn upstream_refresh_token_envelope_requires_configured_key() -> TestResult {
        let _guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
            .lock()
            .map_err(|_| "key encryption key env guard".to_string())?;
        let _env = EnvVarGuard::new(KEY_ENCRYPTION_KEY_ENV, None);
        let err = seal_upstream_refresh_token(
            "upstream-refresh-token-secret",
            uuid::Uuid::new_v4(),
            "https://issuer.example",
            "subject-hash",
            uuid::Uuid::new_v4(),
            1,
        )
        .err()
        .ok_or_else(|| "missing key must fail closed".to_string())?;

        assert_eq!(err, UpstreamRefreshTokenEnvelopeError::KeyMissing);
        Ok(())
    }
}

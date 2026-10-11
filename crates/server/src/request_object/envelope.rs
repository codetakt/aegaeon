use aegaeon_jose::policy::JoseContext;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestObjectEnvelopeError {
    EncryptionNotSupported,
    DecryptionFailed,
    DecryptedPayloadInvalidUtf8,
    DecryptedPayloadNotJwt,
}

impl fmt::Display for RequestObjectEnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncryptionNotSupported => {
                f.write_str("encrypted Request Objects are not supported on this server")
            }
            Self::DecryptionFailed => f.write_str("failed to decrypt encrypted Request Object"),
            Self::DecryptedPayloadInvalidUtf8 => {
                f.write_str("decrypted Request Object payload is not valid UTF-8")
            }
            Self::DecryptedPayloadNotJwt => {
                f.write_str("decrypted Request Object payload is not a compact signed JWT")
            }
        }
    }
}

impl std::error::Error for RequestObjectEnvelopeError {}

fn is_compact_jwe(token: &str) -> bool {
    token.split('.').count() == 5
}

fn is_compact_jws(token: &str) -> bool {
    token.split('.').count() == 3
}

/// Normalise Request Object input to a compact signed JWT for verification.
///
/// - If the input is a compact JWE, this decrypts it using RSA-OAEP + A256GCM
///   with a protected JWT content type and returns the nested compact JWS payload.
/// - Otherwise, returns the original string.
///
/// This explicit-single-key API leaves key selection and protected `kid` policy
/// to its caller. Live server routes use the managed key set entrypoint.
///
/// This is intentionally strict: encrypted Request Objects must decrypt to a
/// nested signed JWT (JWS) so we can apply the RFC 9101 validation rules.
///
/// # Errors
///
/// Returns `RequestObjectEnvelopeError` when an encrypted Request Object cannot
/// be decrypted, decoded as UTF-8, or normalized into a nested signed JWT.
pub fn normalize_request_object_for_verification(
    token: &str,
    request_object_decryption_key_pkcs8_der: Option<&[u8]>,
    jose_header_max_len: usize,
) -> Result<String, RequestObjectEnvelopeError> {
    if !is_compact_jwe(token) {
        return Ok(token.to_string());
    }

    let key = request_object_decryption_key_pkcs8_der
        .ok_or(RequestObjectEnvelopeError::EncryptionNotSupported)?;
    let context = JoseContext::new(jose_header_max_len);
    let plaintext = aegaeon_jose::jwe::decrypt_nested_jwt_rsa_oaep_a256gcm_pkcs8_with_context(
        token, key, context,
    )
    .map_err(|_| RequestObjectEnvelopeError::DecryptionFailed)?;

    normalize_decrypted_payload(plaintext)
}

pub(crate) fn normalize_request_object_with_keyring(
    token: &str,
    key: Option<&crate::oidc::config::OidcRequestObjectEncryptionKey>,
    jose_header_max_len: usize,
) -> Result<String, RequestObjectEnvelopeError> {
    if !is_compact_jwe(token) {
        return Ok(token.to_string());
    }
    let key = key.ok_or(RequestObjectEnvelopeError::EncryptionNotSupported)?;
    let plaintext = aegaeon_jose::jwe::decrypt_nested_jwt_rsa_oaep_a256gcm_with_key_resolver(
        token,
        |kid| key.select_pkcs8(kid),
        JoseContext::new(jose_header_max_len),
    )
    .map_err(|_| RequestObjectEnvelopeError::DecryptionFailed)?;
    normalize_decrypted_payload(plaintext)
}

fn normalize_decrypted_payload(plaintext: Vec<u8>) -> Result<String, RequestObjectEnvelopeError> {
    let inner = String::from_utf8(plaintext)
        .map_err(|_| RequestObjectEnvelopeError::DecryptedPayloadInvalidUtf8)?;
    if !is_compact_jws(&inner) {
        return Err(RequestObjectEnvelopeError::DecryptedPayloadNotJwt);
    }

    Ok(inner)
}

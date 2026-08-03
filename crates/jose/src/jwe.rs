use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use thiserror::Error;

use crate::policy::JoseContext;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum JweError {
    #[error("invalid compact serialization")]
    InvalidSerialization,
    #[error("missing enc header parameter")]
    MissingEnc,
    #[error("unsupported enc algorithm {0}")]
    UnsupportedEnc(String),
    #[error("unsupported alg {0}")]
    UnsupportedAlg(String),
    #[error("header parse error")]
    HeaderParse,
    #[error("unsupported protected header parameter `{0}`")]
    UnsupportedHeader(String),
    #[error("JSON Low* error: {0}")]
    JsonLowStar(#[from] crate::json_lowstar::JsonError),
    #[error("base64 decode error")]
    Base64,
    #[error("invalid cek length")]
    InvalidCekLength,
    #[error("content decryption failed")]
    ContentDecryption,
    #[error("key unwrap failed")]
    KeyUnwrap,
    #[error("invalid RSA private key")]
    InvalidPrivateKey,

    #[error("JWE protected header exceeds configured length limit")]
    HeaderTooLong,
}

#[derive(Debug)]
struct JweHeader {
    alg: Option<String>,
    enc: Option<String>,
}

impl JweHeader {
    fn from_slice(data: &[u8]) -> Result<Self, JweError> {
        let pairs = parse_header_pairs(data)?;
        let mut alg: Option<String> = None;
        let mut enc: Option<String> = None;

        for (key, value) in pairs {
            match key.as_str() {
                "alg" => alg = Some(value),
                "enc" => enc = Some(value),
                // Allow-listed but ignored in this minimal JWE decryptor.
                // (Key allow-listing and critical extensions are enforced by Low*/C.)
                "kid" | "typ" | "cty" => {}
                // Fail closed if the upstream policy ever allows these to surface.
                "crit" | "zip" => return Err(JweError::UnsupportedHeader(key)),
                other => return Err(JweError::UnsupportedHeader(other.to_string())),
            }
        }

        let header = Self { alg, enc };
        header.validate()?;
        Ok(header)
    }

    fn validate(&self) -> Result<(), JweError> {
        let enc = self.enc.as_deref().ok_or(JweError::MissingEnc)?;
        if enc != "A256GCM" {
            return Err(JweError::UnsupportedEnc(enc.to_string()));
        }
        if let Some(alg) = self.alg.as_deref() {
            if alg != "RSA-OAEP" {
                return Err(JweError::UnsupportedAlg(alg.to_string()));
            }
        }
        Ok(())
    }
}

fn parse_header_pairs(data: &[u8]) -> Result<Vec<(String, String)>, JweError> {
    crate::json::parse_json_header(data).map_err(JweError::from)
}

#[cfg(test)]
fn resolve_header_pairs(
    parsed: Result<Vec<(String, String)>, crate::json_lowstar::JsonError>,
    data: &[u8],
) -> Result<Vec<(String, String)>, JweError> {
    crate::json::resolve_json_header_pairs(parsed, data).map_err(JweError::from)
}

/// Decrypt a compact JWE using RSA-OAEP (SHA-1/MGF1) and AES-256-GCM with context.
///
/// The private key is expected to be an unencrypted PKCS#8 DER document.
///
/// # Arguments
///
/// * `jwe` - The compact JWE string
/// * `pkcs8_private_key` - PKCS#8 DER-encoded private key
/// * `context` - The JOSE context for per-request policy (e.g., header length limits)
///
/// # Errors
///
/// Returns [`JweError`] when the compact serialization is malformed, the
/// protected header is invalid, the configured policy rejects the input, or key
/// unwrap / content decryption fails.
pub fn decrypt_rsa_oaep_a256gcm_pkcs8_with_context(
    jwe: &str,
    pkcs8_private_key: &[u8],
    context: JoseContext,
) -> Result<Vec<u8>, JweError> {
    // Perform cheap input validation (header length check) before expensive key parsing
    // This helps prevent DoS attacks via malformed inputs
    let segments: Vec<&str> = jwe.split('.').collect();
    if segments.len() != 5 {
        return Err(JweError::InvalidSerialization);
    }
    if segments[0].len() > context.header_max_length() {
        return Err(JweError::HeaderTooLong);
    }

    decrypt_with_key_unwrapper_with_context(
        jwe,
        |encrypted_key| {
            aegaeon_crypto::jwe::rsa_oaep_unwrap(pkcs8_private_key, encrypted_key)
                .map_err(|_| JweError::KeyUnwrap)
        },
        context,
    )
}

/// Decrypt a compact JWE using RSA-OAEP (SHA-1/MGF1) and AES-256-GCM.
///
/// This function uses the default context (4096 byte header limit).
/// For per-request configuration, use [`decrypt_rsa_oaep_a256gcm_pkcs8_with_context`].
///
/// The private key is expected to be an unencrypted PKCS#8 DER document.
///
/// # Deprecated
///
/// Consider using `decrypt_rsa_oaep_a256gcm_pkcs8_with_context` for explicit per-request policies.
#[allow(deprecated)]
/// # Errors
///
/// Returns the same [`JweError`] values as
/// [`decrypt_rsa_oaep_a256gcm_pkcs8_with_context`].
pub fn decrypt_rsa_oaep_a256gcm_pkcs8(
    jwe: &str,
    pkcs8_private_key: &[u8],
) -> Result<Vec<u8>, JweError> {
    decrypt_rsa_oaep_a256gcm_pkcs8_with_context(jwe, pkcs8_private_key, JoseContext::default())
}

fn decrypt_with_key_unwrapper_with_context<F>(
    jwe: &str,
    unwrap: F,
    context: JoseContext,
) -> Result<Vec<u8>, JweError>
where
    F: Fn(&[u8]) -> Result<Vec<u8>, JweError>,
{
    let segments: Vec<&str> = jwe.split('.').collect();
    if segments.len() != 5 {
        return Err(JweError::InvalidSerialization);
    }
    let protected_header = segments[0];
    if protected_header.len() > context.header_max_length() {
        return Err(JweError::HeaderTooLong);
    }
    let encrypted_key_b64 = segments[1];
    let iv_b64 = segments[2];
    let ciphertext_b64 = segments[3];
    let tag_b64 = segments[4];

    let header_bytes = URL_SAFE_NO_PAD
        .decode(protected_header)
        .map_err(|_| JweError::Base64)?;
    JweHeader::from_slice(&header_bytes)?;

    let encrypted_key = URL_SAFE_NO_PAD
        .decode(encrypted_key_b64)
        .map_err(|_| JweError::Base64)?;
    let iv = URL_SAFE_NO_PAD
        .decode(iv_b64)
        .map_err(|_| JweError::Base64)?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(ciphertext_b64)
        .map_err(|_| JweError::Base64)?;
    let tag = URL_SAFE_NO_PAD
        .decode(tag_b64)
        .map_err(|_| JweError::Base64)?;
    if iv.len() != 12 || tag.len() != 16 {
        return Err(JweError::InvalidSerialization);
    }

    let mut cek = unwrap(&encrypted_key)?;
    if cek.len() != 32 {
        cek.fill(0);
        return Err(JweError::InvalidCekLength);
    }

    let aad = protected_header.as_bytes();
    let plaintext = decrypt_a256gcm(&mut cek, &iv, &ciphertext, &tag, aad)?;
    Ok(plaintext)
}

fn decrypt_a256gcm(
    cek: &mut [u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, JweError> {
    aegaeon_crypto::jwe::decrypt_a256gcm(cek, iv, ciphertext, tag, aad)
        .map_err(|_| JweError::ContentDecryption)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn jwe_header_rejects_zip() -> Result<(), Box<dyn std::error::Error>> {
        let hdr = json!({
            "alg": "RSA-OAEP",
            "enc": "A256GCM",
            "zip": "DEF"
        });
        let data = serde_json::to_vec(&hdr)?;
        let err = JweHeader::from_slice(&data)
            .err()
            .ok_or_else(|| std::io::Error::other("zip must be rejected"))?;
        assert!(
            matches!(err, JweError::UnsupportedHeader(ref field) if field == "zip")
                || matches!(err, JweError::JsonLowStar(_)),
            "Expected UnsupportedHeader(zip) or JsonLowStar error, got: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn jwe_header_rejects_missing_enc() -> Result<(), Box<dyn std::error::Error>> {
        let data = serde_json::to_vec(&json!({
            "alg": "RSA-OAEP"
        }))?;

        let err = JweHeader::from_slice(&data).expect_err("missing enc must be rejected");
        assert!(matches!(err, JweError::MissingEnc));
        Ok(())
    }

    #[test]
    fn jwe_header_rejects_unsupported_enc() -> Result<(), Box<dyn std::error::Error>> {
        let data = serde_json::to_vec(&json!({
            "alg": "RSA-OAEP",
            "enc": "A128GCM"
        }))?;

        let err = JweHeader::from_slice(&data).expect_err("unsupported enc must be rejected");
        assert!(matches!(
            err,
            JweError::UnsupportedEnc(ref enc) if enc == "A128GCM"
        ));
        Ok(())
    }

    #[test]
    fn jwe_header_rejects_crit() -> Result<(), Box<dyn std::error::Error>> {
        let hdr = json!({
            "alg": "RSA-OAEP",
            "enc": "A256GCM",
            "crit": ["exp"]
        });
        let data = serde_json::to_vec(&hdr)?;
        let err = JweHeader::from_slice(&data)
            .err()
            .ok_or_else(|| std::io::Error::other("crit must be rejected"))?;
        assert!(
            matches!(err, JweError::UnsupportedHeader(ref field) if field == "crit")
                || matches!(err, JweError::JsonLowStar(_)),
            "Expected UnsupportedHeader(crit) or JsonLowStar error, got: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn parser_unavailability_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let err = resolve_header_pairs(
            Err(crate::json_lowstar::JsonError::ParserUnavailable),
            br#"{"alg":"RSA-OAEP","enc":"A256GCM"}"#,
        )
        .err()
        .ok_or_else(|| std::io::Error::other("parser unavailability must fail closed"))?;

        assert!(matches!(
            err,
            JweError::JsonLowStar(crate::json_lowstar::JsonError::ParserUnavailable)
        ));
        Ok(())
    }

    #[test]
    fn parser_unavailability_does_not_fallback_to_duplicate_key_scan(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let err = resolve_header_pairs(
            Err(crate::json_lowstar::JsonError::ParserUnavailable),
            br#"{"alg":"RSA-OAEP","alg":"RSA1_5","enc":"A256GCM"}"#,
        )
        .err()
        .ok_or_else(|| std::io::Error::other("parser unavailability must fail closed"))?;

        assert!(matches!(
            err,
            JweError::JsonLowStar(crate::json_lowstar::JsonError::ParserUnavailable)
        ));
        Ok(())
    }

    #[cfg(all(feature = "ffi_jose_header_tlv", not(feature = "verified-claim")))]
    #[test]
    fn ffi_tlv_feature_parses_valid_jwe_header_pairs() -> Result<(), Box<dyn std::error::Error>> {
        let pairs = parse_header_pairs(br#"{"alg":"RSA-OAEP","enc":"A256GCM"}"#)?;
        assert_eq!(
            pairs,
            vec![
                ("alg".to_string(), "RSA-OAEP".to_string()),
                ("enc".to_string(), "A256GCM".to_string())
            ]
        );
        Ok(())
    }

    #[cfg(feature = "verified-claim")]
    #[test]
    fn verified_claim_profile_rejects_jwe_parser_unavailable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let err = resolve_header_pairs(
            Err(crate::json_lowstar::JsonError::ParserUnavailable),
            br#"{"alg":"RSA-OAEP","enc":"A256GCM"}"#,
        )
        .err()
        .ok_or_else(|| std::io::Error::other("strict profile must fail closed"))?;

        assert!(matches!(
            err,
            JweError::JsonLowStar(crate::json_lowstar::JsonError::ParserUnavailable)
        ));
        Ok(())
    }

    #[cfg(all(feature = "ffi_jose_header_tlv", feature = "verified-claim"))]
    #[test]
    fn ffi_tlv_feature_parses_valid_jwe_header_pairs_in_verified_profile(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pairs = parse_header_pairs(br#"{"alg":"RSA-OAEP","enc":"A256GCM"}"#)?;
        assert_eq!(
            pairs,
            vec![
                ("alg".to_string(), "RSA-OAEP".to_string()),
                ("enc".to_string(), "A256GCM".to_string())
            ]
        );
        Ok(())
    }

    #[test]
    fn compat_fallback_does_not_consume_internal_parser_errors(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let err = resolve_header_pairs(
            Err(crate::json_lowstar::JsonError::Internal(
                "unsupported raw JSON backend `future` for surface `jose-header` via AEGAEON_RAW_JSON_BACKEND_JOSE_HEADER".to_string(),
            )),
            br#"{"alg":"RSA-OAEP","enc":"A256GCM"}"#,
        )
        .err()
        .ok_or_else(|| std::io::Error::other("internal parser errors must fail closed"))?;

        assert!(matches!(
            err,
            JweError::JsonLowStar(crate::json_lowstar::JsonError::Internal(ref msg))
                if msg.contains("unsupported raw JSON backend `future`")
        ));
        Ok(())
    }
}

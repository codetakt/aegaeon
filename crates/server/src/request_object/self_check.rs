use aegaeon_jose::RequestObjectClaims;
use ffi::request_object_parser::{self, RequestObjectParseError};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestObjectEverparseSelfCheckError {
    Encode(String),
    ParserUnavailable,
    BufferTooLarge,
    InvalidPayload,
}

impl fmt::Display for RequestObjectEverparseSelfCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encode(msg) => write!(f, "encode error: {msg}"),
            Self::ParserUnavailable => {
                f.write_str("everparse request object parser unavailable in this build")
            }
            Self::BufferTooLarge => {
                f.write_str("everparse request object buffer exceeds u32 length")
            }
            Self::InvalidPayload => {
                f.write_str("everparse request object self-check rejected canonical buffer")
            }
        }
    }
}

impl std::error::Error for RequestObjectEverparseSelfCheckError {}

fn should_run_request_object_everparse_self_check(runtime_enabled: bool) -> bool {
    runtime_enabled || cfg!(feature = "verified-claim")
}

fn finalize_request_object_everparse_self_check(
    required: bool,
    parser_result: Result<(), RequestObjectParseError>,
) -> Result<(), RequestObjectEverparseSelfCheckError> {
    if !required {
        return Ok(());
    }

    match parser_result {
        Ok(()) => Ok(()),
        Err(RequestObjectParseError::ParserUnavailable) => {
            Err(RequestObjectEverparseSelfCheckError::ParserUnavailable)
        }
        Err(RequestObjectParseError::BufferTooLarge) => {
            Err(RequestObjectEverparseSelfCheckError::BufferTooLarge)
        }
        Err(RequestObjectParseError::InvalidPayload) => {
            Err(RequestObjectEverparseSelfCheckError::InvalidPayload)
        }
    }
}

/// Optional defense-in-depth: encode the already-validated Request Object claims
/// into the `EverParse` Request Object binary schema and validate it.
///
/// Notes:
/// - This does **not** validate raw JWT JSON input. It validates a canonical
///   binary encoding derived from Rust-decoded fields.
/// - Enabled by the caller's database-backed runtime policy snapshot, and mandatory in the
///   `verified-claim` profile.
///
/// # Errors
///
/// Returns `RequestObjectEverparseSelfCheckError` when canonical encoding fails
/// or when the `EverParse` self-check rejects the canonical payload.
pub fn everparse_self_check_request_object_claims_with_runtime(
    claims: &RequestObjectClaims,
    expected_audience: &str,
    runtime_enabled: bool,
) -> Result<(), RequestObjectEverparseSelfCheckError> {
    let required = should_run_request_object_everparse_self_check(runtime_enabled);
    if !required {
        return Ok(());
    }

    let buf = encode_request_object_claims(claims, expected_audience)?;
    finalize_request_object_everparse_self_check(
        required,
        request_object_parser::check_request_object_claims(&buf),
    )
}

fn encode_request_object_claims(
    claims: &RequestObjectClaims,
    expected_audience: &str,
) -> Result<Vec<u8>, RequestObjectEverparseSelfCheckError> {
    fn push_u8(out: &mut Vec<u8>, value: u8) {
        out.push(value);
    }

    fn push_u32_le(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u64_le(out: &mut Vec<u8>, value: u64) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn push_bytes_with_u32_len(
        out: &mut Vec<u8>,
        bytes: &[u8],
    ) -> Result<(), RequestObjectEverparseSelfCheckError> {
        let len = u32::try_from(bytes.len())
            .map_err(|_| RequestObjectEverparseSelfCheckError::BufferTooLarge)?;
        push_u32_le(out, len);
        out.extend_from_slice(bytes);
        Ok(())
    }

    fn required_string<'a>(
        label: &'static str,
        value: Option<&'a str>,
    ) -> Result<&'a str, RequestObjectEverparseSelfCheckError> {
        match value {
            Some(v) if !v.trim().is_empty() => Ok(v),
            _ => Err(RequestObjectEverparseSelfCheckError::Encode(format!(
                "{label} is required"
            ))),
        }
    }

    fn optional_string(
        out: &mut Vec<u8>,
        value: Option<&str>,
    ) -> Result<(), RequestObjectEverparseSelfCheckError> {
        match value {
            Some(v) if !v.trim().is_empty() => {
                push_u8(out, 1);
                push_bytes_with_u32_len(out, v.as_bytes())?;
            }
            _ => {
                push_u8(out, 0);
                push_u32_le(out, 0);
            }
        }
        Ok(())
    }

    let aud = required_string("aud", Some(expected_audience))?;
    let exp = claims
        .exp
        .ok_or_else(|| RequestObjectEverparseSelfCheckError::Encode("exp is required".into()))?;
    let nbf = claims
        .nbf
        .ok_or_else(|| RequestObjectEverparseSelfCheckError::Encode("nbf is required".into()))?;
    let client_id = required_string("client_id", claims.client_id.as_deref())?;
    let redirect_uri = required_string("redirect_uri", claims.redirect_uri.as_deref())?;
    let response_type = required_string("response_type", claims.response_type.as_deref())?;
    let scope = required_string("scope", claims.scope.as_deref())?;
    let code_challenge = required_string("code_challenge", claims.code_challenge.as_deref())?;
    let code_challenge_method = required_string(
        "code_challenge_method",
        claims.code_challenge_method.as_deref(),
    )?;
    let jti = required_string("jti", claims.jti.as_deref())?;

    let mut out = Vec::new();
    push_bytes_with_u32_len(&mut out, aud.as_bytes())?;
    push_u64_le(&mut out, exp);
    push_u64_le(&mut out, nbf);
    push_bytes_with_u32_len(&mut out, client_id.as_bytes())?;
    push_bytes_with_u32_len(&mut out, redirect_uri.as_bytes())?;
    push_bytes_with_u32_len(&mut out, response_type.as_bytes())?;
    push_bytes_with_u32_len(&mut out, scope.as_bytes())?;
    optional_string(&mut out, claims.state.as_deref())?;
    optional_string(&mut out, claims.nonce.as_deref())?;
    push_bytes_with_u32_len(&mut out, code_challenge.as_bytes())?;
    push_bytes_with_u32_len(&mut out, code_challenge_method.as_bytes())?;
    optional_string(&mut out, claims.response_mode.as_deref())?;
    push_bytes_with_u32_len(&mut out, jti.as_bytes())?;

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_claims() -> RequestObjectClaims {
        RequestObjectClaims {
            iss: Some("client-123".into()),
            aud: Some(vec!["https://issuer.example".into()]),
            exp: Some(1_900_000_000),
            nbf: Some(1_899_999_900),
            client_id: Some("client-123".into()),
            redirect_uri: Some("https://client.example/cb".into()),
            response_type: Some("code".into()),
            scope: Some("openid profile".into()),
            state: Some("state-123".into()),
            nonce: Some("nonce-123".into()),
            code_challenge: Some("abc123def456ghi789jkl012mno345pq".into()),
            code_challenge_method: Some("S256".into()),
            response_mode: Some("query".into()),
            acr_values: None,
            max_age: None,
            authorization_details: None,
            jti: Some("jti-123".into()),
            extra: None,
        }
    }

    type TestResult = Result<(), String>;

    #[test]
    fn explicit_request_object_everparse_runtime_flag_controls_self_check() {
        assert!(!should_run_request_object_everparse_self_check(false));
        assert!(should_run_request_object_everparse_self_check(true));
    }

    #[cfg(not(feature = "verified-claim"))]
    #[test]
    fn compat_profile_allows_request_object_self_check_bypass_when_disabled() {
        assert!(!should_run_request_object_everparse_self_check(false));
        assert!(should_run_request_object_everparse_self_check(true));
        assert_eq!(
            finalize_request_object_everparse_self_check(
                false,
                Err(RequestObjectParseError::ParserUnavailable),
            ),
            Ok(())
        );
    }

    #[cfg(feature = "verified-claim")]
    #[test]
    fn verified_claim_profile_requires_request_object_self_check_without_env_gate() -> TestResult {
        assert!(should_run_request_object_everparse_self_check(false));

        let err = finalize_request_object_everparse_self_check(
            true,
            Err(RequestObjectParseError::ParserUnavailable),
        )
        .err()
        .ok_or_else(|| "strict profile must fail closed".to_string())?;

        assert_eq!(err, RequestObjectEverparseSelfCheckError::ParserUnavailable);
        Ok(())
    }

    #[test]
    fn request_object_self_check_still_encodes_canonical_claims() -> TestResult {
        let claims = sample_claims();
        let encoded = encode_request_object_claims(&claims, "https://issuer.example")
            .map_err(|err| format!("canonical request object claims encode failed: {err:?}"))?;
        assert!(encoded.len() > 8, "encoded buffer too short");
        Ok(())
    }
}

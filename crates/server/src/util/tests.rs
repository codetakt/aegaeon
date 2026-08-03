use super::*;
use aegaeon_jose::raw_json::{self, RawJsonBackend, RawJsonSurface};
use base64::Engine;
use http::{HeaderMap, HeaderValue};
use serde_json::json;
use std::time::UNIX_EPOCH;

type TestResult = Result<(), String>;

macro_rules! fail_test {
    ($($arg:tt)*) => {
        return Err(format!($($arg)*))
    };
}

macro_rules! must_ok {
    ($result:expr, $context:expr $(,)?) => {
        match $result {
            Ok(value) => value,
            Err(err) => fail_test!("{}: {:?}", $context, err),
        }
    };
}

macro_rules! must_err {
    ($result:expr, $context:expr $(,)?) => {
        match $result {
            Ok(_) => fail_test!("{}", $context),
            Err(err) => err,
        }
    };
}

macro_rules! must_some {
    ($value:expr, $context:expr $(,)?) => {
        match $value {
            Some(value) => value,
            None => fail_test!("{}", $context),
        }
    };
}

struct EnvVarRestore {
    key: &'static str,
    previous: Option<String>,
}

impl Drop for EnvVarRestore {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.as_ref() {
            std::env::set_var(self.key, previous);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

fn override_env_var(key: &'static str, value: Option<&str>) -> EnvVarRestore {
    let previous = std::env::var(key).ok();
    if let Some(value) = value {
        std::env::set_var(key, value);
    } else {
        std::env::remove_var(key);
    }
    EnvVarRestore { key, previous }
}

fn use_verified_jose_header_backend_for_test() -> EnvVarRestore {
    override_env_var(
        raw_json::raw_json_backend_env_var_for_surface(RawJsonSurface::JoseHeader),
        Some("verified-structural-v1"),
    )
}

fn raw_json_env_lock() -> Result<std::sync::MutexGuard<'static, ()>, String> {
    super::RAW_JSON_ENV_GUARD
        .lock()
        .map_err(|err| format!("raw json env guard: {err}"))
}

#[test]
fn is_loopback_host_accepts_dns_ipv4_and_bracketed_ipv6_loopback() {
    assert!(is_loopback_host("localhost"));
    assert!(is_loopback_host("LOCALHOST"));
    assert!(is_loopback_host("127.0.0.1"));
    assert!(is_loopback_host("[::1]"));
    assert!(is_loopback_host("::1"));
    assert!(!is_loopback_host("example.com"));
    assert!(!is_loopback_host("192.0.2.1"));
}

#[test]
fn canonical_url_host_port_brackets_ipv6_and_elides_default_port() -> TestResult {
    let url = must_ok!(url::Url::parse("https://Auth.Example.com:443/path"), "url");
    assert_eq!(
        canonical_url_host_port(&url),
        Some("auth.example.com".to_string())
    );

    let url = must_ok!(url::Url::parse("https://Auth.Example.com:8443/path"), "url");
    assert_eq!(
        canonical_url_host_port(&url),
        Some("auth.example.com:8443".to_string())
    );

    let url = must_ok!(url::Url::parse("https://[::1]:443/path"), "url");
    assert_eq!(canonical_url_host_port(&url), Some("[::1]".to_string()));

    let url = must_ok!(url::Url::parse("https://[::1]:8443/path"), "url");
    assert_eq!(
        canonical_url_host_port(&url),
        Some("[::1]:8443".to_string())
    );
    Ok(())
}

#[test]
fn validate_json_without_duplicate_object_keys_accepts_arrays() {
    assert!(validate_json_without_duplicate_object_keys(
        br#"[{"type":"payment","actions":["read"]}]"#
    )
    .is_ok());
}

#[test]
fn validate_json_without_duplicate_object_keys_rejects_nested_duplicates() -> TestResult {
    let err = must_err!(
        validate_json_without_duplicate_object_keys(
            br#"{"jwk":{"kty":"OKP","x":"first","x":"second"}}"#,
        ),
        "nested duplicate object key must be rejected",
    );

    assert_eq!(err, JsonAdmissionError::DuplicateKey);
    Ok(())
}

#[test]
fn deserialize_compat_json_object_reports_trailing_bytes() -> TestResult {
    let err = must_err!(
        deserialize_compat_json_object_without_duplicate_keys_result_with_backend_for_surface::<
            serde_json::Value,
        >(
            RawJsonSurface::JoseHeader,
            RawJsonBackend::VerifiedStructuralV1,
            br#"{"alg":"HS256"} trailing"#,
        ),
        "trailing bytes must be rejected",
    );

    assert_eq!(err, JsonObjectParseError::TrailingBytes);
    Ok(())
}

#[test]
fn deserialize_compat_json_object_reports_non_object_shape() -> TestResult {
    let err = must_err!(
        deserialize_compat_json_object_without_duplicate_keys_result_with_backend_for_surface::<
            serde_json::Value,
        >(
            RawJsonSurface::JoseHeader,
            RawJsonBackend::VerifiedStructuralV1,
            br#"["alg","HS256"]"#,
        ),
        "non-object payloads must be rejected",
    );

    assert_eq!(err, JsonObjectParseError::InvalidShape);
    Ok(())
}

#[test]
fn deserialize_compat_json_object_reports_duplicate_keys() -> TestResult {
    let err = must_err!(
        deserialize_compat_json_object_without_duplicate_keys_result_with_backend_for_surface::<
            serde_json::Value,
        >(
            RawJsonSurface::JoseHeader,
            RawJsonBackend::VerifiedStructuralV1,
            br#"{"alg":"HS256","alg":"RS256"}"#,
        ),
        "duplicate keys must be rejected",
    );

    assert_eq!(err, JsonObjectParseError::DuplicateKey);
    Ok(())
}

#[test]
fn decode_compact_jwt_header_accepts_valid_header() -> TestResult {
    let _guard = raw_json_env_lock()?;
    let _header_backend = use_verified_jose_header_backend_for_test();
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(br#"{"alg":"RS256","typ":"JWT","kid":"test-key"}"#);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{}"#);
    let token = format!("{header}.{payload}.signature");

    let decoded = must_ok!(
        decode_compact_jwt_header_without_duplicate_keys(&token),
        "valid JOSE header should decode",
    );

    assert_eq!(decoded.alg, jsonwebtoken::Algorithm::RS256);
    assert_eq!(decoded.kid.as_deref(), Some("test-key"));
    Ok(())
}

#[test]
fn decode_compact_jwt_header_rejects_duplicate_keys() -> TestResult {
    let _guard = raw_json_env_lock()?;
    let _header_backend = use_verified_jose_header_backend_for_test();
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(br#"{"alg":"RS256","alg":"HS256","kid":"test-key"}"#);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{}"#);
    let token = format!("{header}.{payload}.signature");

    let err = must_err!(
        decode_compact_jwt_header_without_duplicate_keys(&token),
        "duplicate JOSE header key must fail closed",
    );

    assert_eq!(err, JsonObjectParseError::DuplicateKey);
    Ok(())
}

#[test]
fn decode_compact_jwt_header_rejects_oversized_header_segment() -> TestResult {
    let _guard = raw_json_env_lock()?;

    #[allow(deprecated)]
    let padding = "x".repeat(aegaeon_jose::policy::header_max_len());
    let header = json!({
        "alg": "RS256",
        "padding": padding,
    });
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(must_ok!(serde_json::to_vec(&header), "serialize header"));
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{}"#);
    let token = format!("{header}.{payload}.signature");

    let err = must_err!(
        decode_compact_jwt_header_without_duplicate_keys(&token),
        "oversized JOSE header segment must fail closed",
    );

    assert_eq!(err, JsonObjectParseError::InvalidJson);
    Ok(())
}

#[test]
fn single_header_str_rejects_duplicate_values() -> TestResult {
    let mut headers = HeaderMap::new();
    headers.append(
        "authorization",
        HeaderValue::from_static("Bearer first-token"),
    );
    headers.append(
        "authorization",
        HeaderValue::from_static("Bearer second-token"),
    );

    let err = must_err!(
        single_header_str(&headers, "authorization"),
        "duplicate singleton header must fail closed",
    );

    assert_eq!(err, SingleHeaderError::Multiple);
    Ok(())
}

#[test]
fn unix_epoch_secs_rejects_pre_epoch_time() -> TestResult {
    let pre_epoch = must_some!(
        UNIX_EPOCH.checked_sub(std::time::Duration::from_secs(1)),
        "pre-epoch time is representable",
    );

    assert!(unix_epoch_secs(pre_epoch).is_err());
    Ok(())
}

#[test]
fn deserialize_compat_json_object_reports_unknown_surface_backend_override() -> TestResult {
    let _guard = raw_json_env_lock()?;
    let key = raw_json::raw_json_backend_env_var_for_surface(RawJsonSurface::JoseHeader);
    let _backend = override_env_var(key, Some("future"));

    let result = deserialize_compat_json_object_without_duplicate_keys_result_for_surface::<
        serde_json::Value,
    >(RawJsonSurface::JoseHeader, br#"{"alg":"HS256"}"#);

    let err = must_err!(result, "unknown backend override must fail closed");
    assert_eq!(err, JsonObjectParseError::BackendPolicy);
    Ok(())
}

#[test]
fn extract_bearer_token_accepts_case_insensitive_scheme() -> TestResult {
    let token = must_ok!(
        extract_bearer_token(Some("bEaReR token-value"), None, None),
        "bearer token should parse",
    );
    assert_eq!(token, "token-value");
    Ok(())
}

#[test]
fn extract_bearer_token_rejects_extra_header_segments() -> TestResult {
    let err = must_err!(
        extract_bearer_token(Some("Bearer token-value extra"), None, None),
        "extra header material must be rejected",
    );
    assert_eq!(err, BearerTokenError::InvalidScheme);
    Ok(())
}

#[test]
fn compute_dpop_jkt_rejects_duplicate_header_jwk_members() -> TestResult {
    let _guard = raw_json_env_lock()?;
    let _header_backend = use_verified_jose_header_backend_for_test();
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            br#"{"typ":"dpop+jwt","alg":"EdDSA","jwk":{"kty":"OKP","crv":"Ed25519","x":"first","x":"second"}}"#,
        );
    let proof = format!("{header}.payload.signature");

    assert_eq!(compute_dpop_jkt_from_proof(&proof), None);
    Ok(())
}

#[test]
fn compute_dpop_jkt_rejects_oversized_header_segment() -> TestResult {
    let _guard = raw_json_env_lock()?;
    let _header_backend = use_verified_jose_header_backend_for_test();
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 32]);
    #[allow(deprecated)]
    let padding = "x".repeat(aegaeon_jose::policy::header_max_len());
    let header = json!({
        "typ": "dpop+jwt",
        "alg": "EdDSA",
        "padding": padding,
        "jwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x,
        }
    });
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(must_ok!(serde_json::to_vec(&header), "serialize header"));
    let proof = format!("{header}.payload.signature");

    assert_eq!(compute_dpop_jkt_from_proof(&proof), None);
    Ok(())
}

#[test]
fn compute_dpop_jkt_accepts_typed_ed25519_jwk() -> TestResult {
    let _guard = raw_json_env_lock()?;
    let _header_backend = use_verified_jose_header_backend_for_test();
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 32]);
    let header = json!({
        "typ": "dpop+jwt",
        "alg": "EdDSA",
        "jwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x,
        }
    });
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(must_ok!(serde_json::to_vec(&header), "serialize header"));
    let proof = format!("{header}.payload.signature");

    let jkt = must_some!(
        compute_dpop_jkt_from_proof(&proof),
        "valid Ed25519 JWK thumbprint",
    );
    assert!(!jkt.is_empty());
    Ok(())
}

#[test]
fn compute_dpop_jkt_rejects_untyped_or_padded_jwk_coordinates() -> TestResult {
    let _guard = raw_json_env_lock()?;
    let _header_backend = use_verified_jose_header_backend_for_test();
    let padded_x = format!(
        "{}=",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 32])
    );
    let header = json!({
        "typ": "dpop+jwt",
        "alg": "EdDSA",
        "jwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": padded_x,
        }
    });
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(must_ok!(serde_json::to_vec(&header), "serialize header"));
    let proof = format!("{header}.payload.signature");

    assert_eq!(compute_dpop_jkt_from_proof(&proof), None);
    Ok(())
}

#[test]
fn compute_dpop_jkt_rejects_unsupported_ec_curve() -> TestResult {
    let _guard = raw_json_env_lock()?;
    let _header_backend = use_verified_jose_header_backend_for_test();
    let coordinate = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9_u8; 32]);
    let header = json!({
        "typ": "dpop+jwt",
        "alg": "ES384",
        "jwk": {
            "kty": "EC",
            "crv": "P-384",
            "x": coordinate,
            "y": coordinate,
        }
    });
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(must_ok!(serde_json::to_vec(&header), "serialize header"));
    let proof = format!("{header}.payload.signature");

    assert_eq!(compute_dpop_jkt_from_proof(&proof), None);
    Ok(())
}

#[test]
fn parse_authorization_details_rejects_duplicate_object_keys() -> TestResult {
    let supported_types = vec!["payment".to_string()];
    let err = must_err!(
        parse_authorization_details(r#"[{"type":"unknown","type":"payment"}]"#, &supported_types),
        "duplicate authorization_details keys must fail closed",
    );

    assert_eq!(err, "authorization_details must be a JSON array of objects");
    Ok(())
}

#[test]
fn validate_resource_indicator_enforces_absolute_uri_and_no_fragment() {
    assert!(validate_resource_indicator("https://example.com/resource").is_ok());
    assert!(validate_resource_indicator("/relative").is_err());
    assert!(validate_resource_indicator("https://example.com/resource#frag").is_err());
}

#[test]
fn parse_single_resource_indicator_rejects_multiple_values() {
    let values = vec![
        "https://example.com/one".to_string(),
        "https://example.com/two".to_string(),
    ];
    assert!(parse_single_resource_indicator(&values).is_err());
}

#[test]
fn constant_time_eq_equal_slices() {
    assert!(constant_time_eq(b"secret", b"secret"));
    assert!(constant_time_eq(b"", b""));
}

#[test]
fn constant_time_eq_unequal_slices() {
    assert!(!constant_time_eq(b"secret", b"secreT"));
    assert!(!constant_time_eq(b"abc", b"xyz"));
}

#[test]
fn constant_time_eq_different_lengths() {
    assert!(!constant_time_eq(b"short", b"longer"));
    assert!(!constant_time_eq(b"a", b""));
}

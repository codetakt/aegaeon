//! Low* JSON parser integration
//!
//! This module bridges JSON parsing to the verified Low* implementation
//! by converting JSON strings to the C representation expected by Low*.

use crate::raw_json::{self, RawJsonBackend, RawJsonObjectError, RawJsonSurface};
use crate::raw_json_structural as jose_structural;
use aegaeon_jose_tlv::JoseHeaderParseError;
use ffi::raw_json_structural as ffi_structural;
use serde_json::Value;
use std::ffi::CString;

// Re-export ffi types
pub use ffi::{JsonError, JsonMemberC};

// Value kind constants (from Jose.LowStar.Json)
const JSON_VALUE_STRING: u8 = 0;
const JOSE_HEADER_TRAILING_BYTES_MESSAGE: &str = "trailing bytes after JOSE header JSON object";
const RAW_JSON_STRUCTURAL_TRAILING_BYTES_MESSAGE: &str =
    "trailing bytes after structural raw JSON object";

/// Holder for allocated strings to ensure proper cleanup
struct MemberData {
    _key: CString,
    _value: Option<CString>, // None for null values
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JoseHeaderStringMember {
    pub key: String,
    pub value: Option<String>,
}

#[cfg(test)]
fn map_raw_json_error(err: RawJsonObjectError) -> JsonError {
    match err {
        RawJsonObjectError::InvalidBackendPolicy(err) => JsonError::Internal(err.to_string()),
        RawJsonObjectError::DuplicateKey => JsonError::PolicyViolation("duplicate-key".to_string()),
        RawJsonObjectError::TrailingBytes(_) => {
            JsonError::TrailingBytes(JOSE_HEADER_TRAILING_BYTES_MESSAGE.to_string())
        }
        RawJsonObjectError::InvalidJson(err) | RawJsonObjectError::InvalidShape(err) => {
            JsonError::Internal(format!("JSON parse error: {err}"))
        }
    }
}

fn invalid_jose_header_value_type_error(key: &str) -> JsonError {
    JsonError::Internal(format!(
        "JSON parse error: JOSE header value for key `{key}` must be string or null"
    ))
}

fn decode_structural_key_bytes(raw_key: &[u8]) -> Result<String, JsonError> {
    let mut quoted = Vec::with_capacity(raw_key.len() + 2);
    quoted.push(b'"');
    quoted.extend_from_slice(raw_key);
    quoted.push(b'"');

    if let Ok(key) = serde_json::from_slice::<String>(&quoted) {
        return Ok(key);
    }

    if String::from_utf8(raw_key.to_vec()).is_err() {
        return Err(JsonError::InvalidKeyEncoding(
            JoseHeaderParseError::NonUtf8Key.to_string(),
        ));
    }

    Err(JsonError::Internal(
        "JSON parse error: structural key bytes were not valid JSON string content".to_string(),
    ))
}

fn validate_jose_header_string_members(
    members: &[JoseHeaderStringMember],
) -> Result<(), JsonError> {
    let mut seen = std::collections::HashSet::with_capacity(members.len());

    for member in members {
        if !member.key.is_ascii() {
            return Err(JsonError::InvalidKeyEncoding(
                JoseHeaderParseError::NonAsciiKey.to_string(),
            ));
        }

        if !seen.insert(member.key.as_str()) {
            return Err(JsonError::PolicyViolation("duplicate-key".to_string()));
        }
    }

    Ok(())
}

#[cfg(test)]
fn raw_json_members_to_string_members(
    members: Vec<raw_json::RawJsonObjectMember>,
) -> Result<Vec<JoseHeaderStringMember>, JsonError> {
    let mut normalized = Vec::with_capacity(members.len());

    for member in members {
        let value = match member.value {
            Value::String(value) => Some(value),
            Value::Null => None,
            _ => return Err(invalid_jose_header_value_type_error(&member.key)),
        };

        normalized.push(JoseHeaderStringMember {
            key: member.key,
            value,
        });
    }

    validate_jose_header_string_members(&normalized)?;
    Ok(normalized)
}

fn jose_header_string_members_to_raw(
    members: Vec<JoseHeaderStringMember>,
) -> Vec<raw_json::RawJsonObjectMember> {
    members
        .into_iter()
        .map(|member| raw_json::RawJsonObjectMember {
            key: member.key,
            value: member.value.map_or(Value::Null, Value::String),
        })
        .collect()
}

#[cfg(test)]
fn jose_header_string_members_to_pairs(
    members: Vec<JoseHeaderStringMember>,
) -> Vec<(String, String)> {
    members
        .into_iter()
        .filter_map(|member| member.value.map(|value| (member.key, value)))
        .collect()
}

fn map_structural_raw_json_error_to_raw_json_object_error(
    error: ffi_structural::RawJsonStructuralParseError,
) -> RawJsonObjectError {
    match error {
        ffi_structural::RawJsonStructuralParseError::InvalidJson
        | ffi_structural::RawJsonStructuralParseError::BufferTooLarge
        | ffi_structural::RawJsonStructuralParseError::Internal => RawJsonObjectError::InvalidJson(
            serde_json::Error::io(std::io::Error::other(error.to_string())),
        ),
        ffi_structural::RawJsonStructuralParseError::ParserUnavailable => {
            RawJsonObjectError::InvalidJson(serde_json::Error::io(std::io::Error::other(
                error.to_string(),
            )))
        }
        ffi_structural::RawJsonStructuralParseError::InvalidShape => {
            RawJsonObjectError::InvalidShape(serde_json::Error::io(std::io::Error::other(
                error.to_string(),
            )))
        }
        ffi_structural::RawJsonStructuralParseError::TrailingBytes => {
            RawJsonObjectError::TrailingBytes(serde_json::Error::io(std::io::Error::other(
                JOSE_HEADER_TRAILING_BYTES_MESSAGE,
            )))
        }
    }
}

fn map_structural_adapter_error_to_raw_json_object_error(error: JsonError) -> RawJsonObjectError {
    match error {
        JsonError::PolicyViolation(policy) if policy == "duplicate-key" => {
            RawJsonObjectError::DuplicateKey
        }
        JsonError::TrailingBytes(message) => {
            RawJsonObjectError::TrailingBytes(serde_json::Error::io(std::io::Error::other(message)))
        }
        JsonError::InvalidKeyEncoding(message)
        | JsonError::UnknownKey(message)
        | JsonError::InvalidValueUtf8(message)
        | JsonError::BufferTooShort(message)
        | JsonError::PolicyViolation(message)
        | JsonError::Internal(message) => {
            RawJsonObjectError::InvalidShape(serde_json::Error::io(std::io::Error::other(message)))
        }
        JsonError::ParserUnavailable => {
            RawJsonObjectError::InvalidJson(serde_json::Error::io(std::io::Error::other(
                ffi_structural::RawJsonStructuralParseError::ParserUnavailable.to_string(),
            )))
        }
    }
}

fn map_structural_parse_error_to_json_error(
    error: ffi_structural::RawJsonStructuralParseError,
) -> JsonError {
    match error {
        ffi_structural::RawJsonStructuralParseError::ParserUnavailable => {
            JsonError::ParserUnavailable
        }
        ffi_structural::RawJsonStructuralParseError::TrailingBytes => {
            JsonError::TrailingBytes(JOSE_HEADER_TRAILING_BYTES_MESSAGE.to_string())
        }
        ffi_structural::RawJsonStructuralParseError::InvalidJson
        | ffi_structural::RawJsonStructuralParseError::InvalidShape
        | ffi_structural::RawJsonStructuralParseError::BufferTooLarge
        | ffi_structural::RawJsonStructuralParseError::Internal => {
            JsonError::Internal(format!("JSON parse error: {error}"))
        }
    }
}

fn convert_structural_value_kind(
    kind: ffi_structural::RawJsonStructuralValueKind,
) -> jose_structural::RawJsonStructuralValueKind {
    match kind {
        ffi_structural::RawJsonStructuralValueKind::String => {
            jose_structural::RawJsonStructuralValueKind::String
        }
        ffi_structural::RawJsonStructuralValueKind::Null => {
            jose_structural::RawJsonStructuralValueKind::Null
        }
        ffi_structural::RawJsonStructuralValueKind::Number => {
            jose_structural::RawJsonStructuralValueKind::Number
        }
        ffi_structural::RawJsonStructuralValueKind::Bool => {
            jose_structural::RawJsonStructuralValueKind::Bool
        }
        ffi_structural::RawJsonStructuralValueKind::Object => {
            jose_structural::RawJsonStructuralValueKind::Object
        }
        ffi_structural::RawJsonStructuralValueKind::Array => {
            jose_structural::RawJsonStructuralValueKind::Array
        }
    }
}

fn convert_structural_parse_result(
    result: ffi_structural::RawJsonStructuralParseResult,
) -> jose_structural::RawJsonStructuralParseResult {
    jose_structural::RawJsonStructuralParseResult {
        members: result
            .members
            .into_iter()
            .map(|member| jose_structural::RawJsonStructuralMember {
                key: member.key,
                value_kind: convert_structural_value_kind(member.value_kind),
                value_span: jose_structural::RawJsonStructuralSpan {
                    offset: member.value_span.offset,
                    len: member.value_span.len,
                },
            })
            .collect(),
        consumed_len: result.consumed_len,
    }
}

pub(crate) fn parse_json_header_structural_result_via_ffi(
    bytes: &[u8],
) -> Result<
    jose_structural::RawJsonStructuralParseResult,
    ffi_structural::RawJsonStructuralParseError,
> {
    let result = ffi_structural::parse_raw_json_structural(bytes)?;
    Ok(convert_structural_parse_result(result))
}

fn structural_json_header_members_to_string_members(
    bytes: &[u8],
    parse_result: &jose_structural::RawJsonStructuralParseResult,
) -> Result<Vec<JoseHeaderStringMember>, JsonError> {
    if parse_result.has_trailing_bytes(bytes) {
        return Err(JsonError::TrailingBytes(
            JOSE_HEADER_TRAILING_BYTES_MESSAGE.to_string(),
        ));
    }

    let mut members = Vec::with_capacity(parse_result.members.len());
    for member in &parse_result.members {
        let key = decode_structural_key_bytes(&member.key)?;

        let value = match member.value_kind {
            jose_structural::RawJsonStructuralValueKind::String => {
                let value_bytes = member.value_slice(bytes).ok_or_else(|| {
                    JsonError::Internal(format!(
                        "JSON parse error: structural value span out of bounds for key `{key}`"
                    ))
                })?;
                Some(
                    serde_json::from_slice::<String>(value_bytes)
                        .map_err(|err| JsonError::Internal(format!("JSON parse error: {err}")))?,
                )
            }
            jose_structural::RawJsonStructuralValueKind::Null => None,
            jose_structural::RawJsonStructuralValueKind::Number
            | jose_structural::RawJsonStructuralValueKind::Bool
            | jose_structural::RawJsonStructuralValueKind::Object
            | jose_structural::RawJsonStructuralValueKind::Array => {
                return Err(invalid_jose_header_value_type_error(&key))
            }
        };

        members.push(JoseHeaderStringMember { key, value });
    }

    validate_jose_header_string_members(&members)?;
    Ok(members)
}

fn structural_json_members_to_raw(
    bytes: &[u8],
    parse_result: &jose_structural::RawJsonStructuralParseResult,
) -> Result<Vec<raw_json::RawJsonObjectMember>, RawJsonObjectError> {
    if parse_result.has_trailing_bytes(bytes) {
        return Err(RawJsonObjectError::TrailingBytes(serde_json::Error::io(
            std::io::Error::other(RAW_JSON_STRUCTURAL_TRAILING_BYTES_MESSAGE),
        )));
    }

    let mut members = Vec::with_capacity(parse_result.members.len());
    for member in &parse_result.members {
        let key = decode_structural_key_bytes(&member.key)
            .map_err(map_structural_adapter_error_to_raw_json_object_error)?;
        let value_bytes = member.value_slice(bytes).ok_or_else(|| {
            RawJsonObjectError::InvalidShape(serde_json::Error::io(std::io::Error::other(format!(
                "JSON parse error: structural value span out of bounds for key `{key}`"
            ))))
        })?;
        let value = serde_json::from_slice::<Value>(value_bytes).map_err(|err| {
            RawJsonObjectError::InvalidShape(serde_json::Error::io(std::io::Error::other(format!(
                "JSON parse error: {err}"
            ))))
        })?;

        members.push(raw_json::RawJsonObjectMember { key, value });
    }

    Ok(members)
}

pub(crate) fn structural_json_header_members_to_raw(
    bytes: &[u8],
    parse_result: &jose_structural::RawJsonStructuralParseResult,
) -> Result<Vec<raw_json::RawJsonObjectMember>, JsonError> {
    structural_json_header_members_to_string_members(bytes, parse_result)
        .map(jose_header_string_members_to_raw)
}

pub(crate) fn parse_json_header_members_via_structural_ffi_for_raw_json(
    bytes: &[u8],
) -> Result<Vec<raw_json::RawJsonObjectMember>, RawJsonObjectError> {
    let parse_result = parse_json_header_structural_result_via_ffi(bytes)
        .map_err(map_structural_raw_json_error_to_raw_json_object_error)?;
    structural_json_header_members_to_raw(bytes, &parse_result)
        .map_err(map_structural_adapter_error_to_raw_json_object_error)
}

pub(crate) fn parse_json_members_via_structural_ffi_for_raw_json(
    bytes: &[u8],
) -> Result<Vec<raw_json::RawJsonObjectMember>, RawJsonObjectError> {
    let parse_result = parse_json_header_structural_result_via_ffi(bytes)
        .map_err(map_structural_raw_json_error_to_raw_json_object_error)?;
    structural_json_members_to_raw(bytes, &parse_result)
}

fn parse_json_header_string_members_with_backend(
    bytes: &[u8],
    backend: RawJsonBackend,
) -> Result<Vec<JoseHeaderStringMember>, JsonError> {
    match backend {
        #[cfg(test)]
        RawJsonBackend::SerdeCompat => {
            let report = raw_json::parse_json_object_members_with_backend_for_surface(
                RawJsonSurface::JoseHeader,
                RawJsonBackend::SerdeCompat,
                bytes,
            )
            .map_err(map_raw_json_error)?;
            raw_json_members_to_string_members(report.value)
        }
        #[cfg(not(test))]
        RawJsonBackend::SerdeCompat => Err(JsonError::Internal(
            "serde-compat raw JSON backend is not available in normal builds".to_string(),
        )),
        RawJsonBackend::VerifiedStructuralV1 => {
            let parse_result = parse_json_header_structural_result_via_ffi(bytes)
                .map_err(map_structural_parse_error_to_json_error)?;
            structural_json_header_members_to_string_members(bytes, &parse_result)
        }
    }
}

pub(crate) fn parse_json_header_string_members(
    bytes: &[u8],
) -> Result<Vec<JoseHeaderStringMember>, JsonError> {
    let policy = raw_json::backend_policy_for_surface(RawJsonSurface::JoseHeader)
        .map_err(|err| JsonError::Internal(err.to_string()))?;
    parse_json_header_string_members_with_backend(bytes, policy.backend)
}

#[cfg(test)]
pub(crate) fn parse_json_header_pairs_compat(
    bytes: &[u8],
) -> Result<Vec<(String, String)>, JsonError> {
    let _policy = raw_json::backend_policy_for_surface(RawJsonSurface::JoseHeader)
        .map_err(|err| JsonError::Internal(err.to_string()))?;
    let members =
        parse_json_header_string_members_with_backend(bytes, RawJsonBackend::SerdeCompat)?;
    Ok(jose_header_string_members_to_pairs(members))
}

/// Parse JSON header bytes using Low* verified implementation
///
/// # Errors
///
/// Returns [`JsonError`] when the raw JSON object is invalid, contains
/// duplicate keys, or the Low* bridge rejects the normalized member list.
pub fn parse_json_header_lowstar(bytes: &[u8]) -> Result<Vec<(String, String)>, JsonError> {
    // Step 1: Decode the selected raw-bytes surface into a narrow
    // key + (string | null) representation without promoting a broad JSON AST
    // on the verified structural path.
    let raw_members = parse_json_header_string_members(bytes)?;

    // Step 2: Convert to json_member_c array
    let mut member_data = Vec::with_capacity(raw_members.len());
    let mut members = Vec::new();

    for member in raw_members {
        let key_cstring = CString::new(member.key)
            .map_err(|_| JsonError::InvalidKeyEncoding("key contains null byte".to_string()))?;

        let (value_kind, value_cstring, value_len) = match member.value {
            Some(value) => {
                let cs = CString::new(value).map_err(|_| {
                    JsonError::InvalidValueUtf8("value contains null byte".to_string())
                })?;
                let len = u32::try_from(cs.as_bytes().len()).map_err(|_| {
                    JsonError::Internal("value length exceeds u32::MAX".to_string())
                })?;
                (JSON_VALUE_STRING, Some(cs), len)
            }
            None => continue,
        };

        let member = JsonMemberC {
            key_buf: key_cstring.as_ptr().cast::<u8>(),
            key_len: u32::try_from(key_cstring.as_bytes().len())
                .map_err(|_| JsonError::Internal("key length exceeds u32::MAX".to_string()))?,
            value_kind,
            padding: [0; 3],
            value_buf: value_cstring
                .as_ref()
                .map_or(std::ptr::null(), |cs| cs.as_ptr().cast::<u8>()),
            value_len,
        };

        member_data.push(MemberData {
            _key: key_cstring,
            _value: value_cstring,
        });
        members.push(member);
    }

    // Step 3: Call Low* implementation
    let result = ::ffi::parse_json_entries_safe(&members)?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw_json_structural::{
        RawJsonStructuralMember, RawJsonStructuralParseResult, RawJsonStructuralSpan,
        RawJsonStructuralValueKind,
    };
    use std::error::Error;
    use std::io::Error as IoError;
    use std::sync::MutexGuard;

    type TestResult = Result<(), Box<dyn Error>>;
    type HeaderMembersResult = Result<Vec<raw_json::RawJsonObjectMember>, JsonError>;

    fn lock_raw_json_env_guard() -> Result<MutexGuard<'static, ()>, IoError> {
        crate::raw_json::RAW_JSON_TEST_ENV_GUARD
            .lock()
            .map_err(|_| IoError::other("raw json env guard"))
    }

    fn run_structural_ffi_parity_case(
        bytes: &[u8],
    ) -> Result<Option<(HeaderMembersResult, HeaderMembersResult)>, IoError> {
        let _guard = lock_raw_json_env_guard()?;
        let compat = parse_json_header_members_via_serde_compat_for_tests(bytes);
        let structural = parse_json_header_members_via_structural_ffi_for_tests(bytes);

        if structural == Err(JsonError::ParserUnavailable) {
            return Ok(None);
        }

        Ok(Some((compat, structural)))
    }

    fn parse_json_header_members_via_serde_compat_for_tests(bytes: &[u8]) -> HeaderMembersResult {
        parse_json_header_string_members_with_backend(bytes, RawJsonBackend::SerdeCompat)
            .map(jose_header_string_members_to_raw)
    }

    fn parse_json_header_members_via_structural_ffi_for_tests(bytes: &[u8]) -> HeaderMembersResult {
        let parse_result = parse_json_header_structural_result_via_ffi(bytes)
            .map_err(map_structural_parse_error_to_json_error)?;
        structural_json_header_members_to_raw(bytes, &parse_result)
    }

    fn assert_structural_ffi_matches_compat_when_available(bytes: &[u8]) -> TestResult {
        if let Some((compat, structural)) = run_structural_ffi_parity_case(bytes)? {
            assert_eq!(structural, compat);
        }
        Ok(())
    }

    fn assert_structural_ffi_matches_compat_internal_error_when_available(
        bytes: &[u8],
    ) -> TestResult {
        if let Some((compat, structural)) = run_structural_ffi_parity_case(bytes)? {
            assert!(matches!(compat, Err(JsonError::Internal(_))));
            assert!(matches!(structural, Err(JsonError::Internal(_))));
        }
        Ok(())
    }

    // Helper macro to skip test when Low* FFI is unavailable
    macro_rules! skip_if_lowstar_unavailable {
        () => {
            if ffi::is_lowstar_unavailable() {
                eprintln!("Skipping: Low* FFI unavailable in this build");
                return Ok(());
            }
        };
    }

    fn structural_result_when_available<T>(
        result: Result<T, JsonError>,
    ) -> Result<Option<T>, JsonError> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(JsonError::ParserUnavailable) => Ok(None),
            Err(err) => Err(err),
        }
    }

    #[test]
    fn parse_minimal_header() -> TestResult {
        skip_if_lowstar_unavailable!();
        let _guard = lock_raw_json_env_guard()?;
        let json = br#"{"alg":"HS256"}"#;
        let result = parse_json_header_lowstar(json)?;
        assert_eq!(result, vec![("alg".to_string(), "HS256".to_string())]);
        Ok(())
    }

    #[test]
    fn parse_header_with_multiple_fields() -> TestResult {
        skip_if_lowstar_unavailable!();
        let _guard = lock_raw_json_env_guard()?;
        let json = br#"{"alg":"HS256","typ":"JWT","kid":"key-1"}"#;
        let result = parse_json_header_lowstar(json)?;

        // Convert to map for easier comparison (order may vary)
        let map: std::collections::HashMap<_, _> = result.into_iter().collect();
        assert_eq!(map.get("alg").map(String::as_str), Some("HS256"));
        assert_eq!(map.get("typ").map(String::as_str), Some("JWT"));
        assert_eq!(map.get("kid").map(String::as_str), Some("key-1"));
        Ok(())
    }

    #[test]
    fn parse_header_with_null_value() -> TestResult {
        skip_if_lowstar_unavailable!();
        let _guard = lock_raw_json_env_guard()?;
        let json = br#"{"alg":"HS256","kid":null}"#;
        let result = parse_json_header_lowstar(json)?;

        // Null values should be preserved as empty strings or omitted by Low*
        let map: std::collections::HashMap<_, _> = result.into_iter().collect();
        assert_eq!(map.get("alg").map(String::as_str), Some("HS256"));
        // Low* may omit null values
        Ok(())
    }

    #[test]
    fn compat_pairs_reject_duplicate_keys() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        assert_eq!(
            parse_json_header_pairs_compat(br#"{"alg":"HS256","alg":"RS256"}"#).err(),
            Some(JsonError::PolicyViolation("duplicate-key".to_string()))
        );
        Ok(())
    }

    #[test]
    fn compat_pairs_skip_null_values() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let pairs = parse_json_header_pairs_compat(br#"{"alg":"HS256","kid":null,"typ":"JWT"}"#)?;
        assert_eq!(
            pairs,
            vec![
                ("alg".to_string(), "HS256".to_string()),
                ("typ".to_string(), "JWT".to_string())
            ]
        );
        Ok(())
    }

    #[test]
    fn compat_pairs_reject_non_ascii_keys() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        assert_eq!(
            parse_json_header_pairs_compat(br#"{"\u00e5lg":"HS256"}"#),
            Err(JsonError::InvalidKeyEncoding(
                JoseHeaderParseError::NonAsciiKey.to_string()
            ))
        );
        Ok(())
    }

    #[test]
    fn compat_pairs_reject_trailing_bytes() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        assert_eq!(
            parse_json_header_pairs_compat(br#"{"alg":"HS256"}x"#),
            Err(JsonError::TrailingBytes(
                "trailing bytes after JOSE header JSON object".to_string()
            ))
        );
        Ok(())
    }

    #[test]
    fn compat_pairs_reject_unknown_backend_override() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let key = crate::raw_json::raw_json_backend_env_var_for_surface(RawJsonSurface::JoseHeader);
        let previous = std::env::var(key).ok();
        std::env::set_var(key, "future");

        let result = parse_json_header_pairs_compat(br#"{"alg":"HS256","typ":"JWT"}"#);

        if let Some(prev) = previous {
            std::env::set_var(key, prev);
        } else {
            std::env::remove_var(key);
        }

        let err = result
            .err()
            .ok_or_else(|| IoError::other("unknown backend override must fail closed"))?;
        assert!(matches!(
            err,
            JsonError::Internal(ref msg)
                if msg.contains("unsupported raw JSON backend `future`")
        ));
        Ok(())
    }

    #[test]
    fn structural_backend_override_normalizes_simple_jose_header() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let key = crate::raw_json::raw_json_backend_env_var_for_surface(RawJsonSurface::JoseHeader);
        let previous = std::env::var(key).ok();
        std::env::set_var(key, "verified-structural-v1");

        let result = parse_json_header_lowstar(br#"{"alg":"HS256","kid":"structural"}"#);

        if let Some(prev) = previous {
            std::env::set_var(key, prev);
        } else {
            std::env::remove_var(key);
        }

        let Some(pairs) = structural_result_when_available(result)? else {
            return Ok(());
        };
        assert_eq!(
            pairs,
            vec![
                ("alg".to_string(), "HS256".to_string()),
                ("kid".to_string(), "structural".to_string())
            ]
        );
        Ok(())
    }

    #[test]
    fn structural_backend_override_normalizes_escaped_ascii_key() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let key = crate::raw_json::raw_json_backend_env_var_for_surface(RawJsonSurface::JoseHeader);
        let previous = std::env::var(key).ok();
        std::env::set_var(key, "verified-structural-v1");

        let result = parse_json_header_lowstar(br#"{"\u0061lg":"HS256"}"#);

        if let Some(prev) = previous {
            std::env::set_var(key, prev);
        } else {
            std::env::remove_var(key);
        }

        let Some(pairs) = structural_result_when_available(result)? else {
            return Ok(());
        };
        assert_eq!(pairs, vec![("alg".to_string(), "HS256".to_string())]);
        Ok(())
    }

    #[test]
    fn parse_rejects_non_string_values() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let json = br#"{"alg":"HS256","exp":1234567890}"#;
        let result = parse_json_header_lowstar(json);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn structural_adapter_round_trips_string_and_null_members() -> TestResult {
        let json = br#"{"alg":"HS256","kid":null}"#;
        let parse_result = RawJsonStructuralParseResult {
            members: vec![
                RawJsonStructuralMember {
                    key: b"alg".to_vec(),
                    value_kind: RawJsonStructuralValueKind::String,
                    value_span: RawJsonStructuralSpan { offset: 7, len: 7 },
                },
                RawJsonStructuralMember {
                    key: b"kid".to_vec(),
                    value_kind: RawJsonStructuralValueKind::Null,
                    value_span: RawJsonStructuralSpan { offset: 21, len: 4 },
                },
            ],
            consumed_len: u32::try_from(json.len())?,
        };

        let members = structural_json_header_members_to_raw(json, &parse_result)?;
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].key, "alg");
        assert_eq!(members[0].value, Value::String("HS256".to_string()));
        assert_eq!(members[1].key, "kid");
        assert_eq!(members[1].value, Value::Null);
        Ok(())
    }

    #[test]
    fn structural_adapter_decodes_escaped_key_bytes() -> TestResult {
        let json = br#"{"\u0061lg":"HS256"}"#;
        let parse_result = RawJsonStructuralParseResult {
            members: vec![RawJsonStructuralMember {
                key: br#"\u0061lg"#.to_vec(),
                value_kind: RawJsonStructuralValueKind::String,
                value_span: RawJsonStructuralSpan { offset: 12, len: 7 },
            }],
            consumed_len: u32::try_from(json.len())?,
        };

        let members = structural_json_header_members_to_raw(json, &parse_result)?;
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].key, "alg");
        assert_eq!(members[0].value, Value::String("HS256".to_string()));
        Ok(())
    }

    #[test]
    fn structural_adapter_rejects_non_ascii_keys() {
        let json = br#"{"alg":"HS256"}"#;
        let parse_result = RawJsonStructuralParseResult {
            members: vec![RawJsonStructuralMember {
                key: "ålg".as_bytes().to_vec(),
                value_kind: RawJsonStructuralValueKind::String,
                value_span: RawJsonStructuralSpan { offset: 7, len: 7 },
            }],
            consumed_len: u32::try_from(json.len()).unwrap_or(u32::MAX),
        };

        assert_eq!(
            structural_json_header_members_to_raw(json, &parse_result),
            Err(JsonError::InvalidKeyEncoding(
                JoseHeaderParseError::NonAsciiKey.to_string()
            ))
        );
    }

    #[test]
    fn structural_adapter_rejects_non_string_or_null_value_kinds() {
        let json = br#"{"exp":123}"#;
        let parse_result = RawJsonStructuralParseResult {
            members: vec![RawJsonStructuralMember {
                key: b"exp".to_vec(),
                value_kind: RawJsonStructuralValueKind::Number,
                value_span: RawJsonStructuralSpan { offset: 7, len: 3 },
            }],
            consumed_len: u32::try_from(json.len()).unwrap_or(u32::MAX),
        };

        assert_eq!(
            structural_json_header_members_to_raw(json, &parse_result),
            Err(JsonError::Internal(
                "JSON parse error: JOSE header value for key `exp` must be string or null"
                    .to_string()
            ))
        );
    }

    #[test]
    fn structural_adapter_rejects_trailing_bytes_even_on_successful_parse_result() {
        let json = br#"{"alg":"HS256"}x"#;
        let parse_result = RawJsonStructuralParseResult {
            members: vec![RawJsonStructuralMember {
                key: b"alg".to_vec(),
                value_kind: RawJsonStructuralValueKind::String,
                value_span: RawJsonStructuralSpan { offset: 7, len: 7 },
            }],
            consumed_len: 15,
        };

        assert_eq!(
            structural_json_header_members_to_raw(json, &parse_result),
            Err(JsonError::TrailingBytes(
                JOSE_HEADER_TRAILING_BYTES_MESSAGE.to_string()
            ))
        );
    }

    #[test]
    fn structural_adapter_rejects_out_of_bounds_spans() {
        let json = br#"{"alg":"HS256"}"#;
        let parse_result = RawJsonStructuralParseResult {
            members: vec![RawJsonStructuralMember {
                key: b"alg".to_vec(),
                value_kind: RawJsonStructuralValueKind::String,
                value_span: RawJsonStructuralSpan {
                    offset: 999,
                    len: 7,
                },
            }],
            consumed_len: u32::try_from(json.len()).unwrap_or(u32::MAX),
        };

        assert_eq!(
            structural_json_header_members_to_raw(json, &parse_result),
            Err(JsonError::Internal(
                "JSON parse error: structural value span out of bounds for key `alg`".to_string()
            ))
        );
    }

    #[test]
    fn structural_ffi_matches_compat_for_escaped_ascii_keys_when_available() -> TestResult {
        assert_structural_ffi_matches_compat_when_available(br#"{"\u0061lg":"HS256"}"#)
    }

    #[test]
    fn structural_raw_json_error_mapping_preserves_contract_boundaries() {
        assert!(matches!(
            map_structural_raw_json_error_to_raw_json_object_error(
                ffi_structural::RawJsonStructuralParseError::InvalidJson
            ),
            RawJsonObjectError::InvalidJson(_)
        ));
        assert!(matches!(
            map_structural_raw_json_error_to_raw_json_object_error(
                ffi_structural::RawJsonStructuralParseError::InvalidShape
            ),
            RawJsonObjectError::InvalidShape(_)
        ));
        assert!(matches!(
            map_structural_raw_json_error_to_raw_json_object_error(
                ffi_structural::RawJsonStructuralParseError::TrailingBytes
            ),
            RawJsonObjectError::TrailingBytes(_)
        ));
        assert!(matches!(
            map_structural_raw_json_error_to_raw_json_object_error(
                ffi_structural::RawJsonStructuralParseError::ParserUnavailable
            ),
            RawJsonObjectError::InvalidJson(ref inner)
                if inner
                    .to_string()
                    .contains("raw JSON structural parser unavailable for this input or build")
        ));
    }

    #[test]
    fn structural_adapter_error_mapping_preserves_duplicate_key_and_shape_errors() {
        assert!(matches!(
            map_structural_adapter_error_to_raw_json_object_error(JsonError::PolicyViolation(
                "duplicate-key".to_string()
            )),
            RawJsonObjectError::DuplicateKey
        ));
        assert!(matches!(
            map_structural_adapter_error_to_raw_json_object_error(JsonError::Internal(
                "bad header value".to_string()
            )),
            RawJsonObjectError::InvalidShape(_)
        ));
    }

    #[test]
    fn structural_ffi_matches_compat_for_empty_header_when_available() -> TestResult {
        assert_structural_ffi_matches_compat_when_available(br#"{}"#)
    }

    #[test]
    fn structural_ffi_matches_compat_for_simple_string_member_when_available() -> TestResult {
        assert_structural_ffi_matches_compat_when_available(br#"{"alg":"HS256"}"#)
    }

    #[test]
    fn structural_ffi_matches_compat_for_string_and_null_members_when_available() -> TestResult {
        assert_structural_ffi_matches_compat_when_available(br#"{"alg":"HS256","kid":null}"#)
    }

    #[test]
    fn structural_ffi_matches_compat_for_duplicate_keys_when_available() -> TestResult {
        assert_structural_ffi_matches_compat_when_available(br#"{"alg":"HS256","alg":"RS256"}"#)
    }

    #[test]
    fn structural_ffi_matches_compat_for_trailing_bytes_when_available() -> TestResult {
        assert_structural_ffi_matches_compat_when_available(br#"{"alg":"HS256"}x"#)
    }

    #[test]
    fn structural_ffi_matches_compat_for_escaped_strings_when_available() -> TestResult {
        assert_structural_ffi_matches_compat_when_available(
            br#"{"alg":"HS\u0032\u0035\u0036","kid":"line\nwrap"}"#,
        )
    }

    #[test]
    fn structural_ffi_matches_compat_for_non_ascii_keys_when_available() -> TestResult {
        assert_structural_ffi_matches_compat_when_available(br#"{"\u00e5lg":"HS256"}"#)
    }

    #[test]
    fn structural_ffi_matches_compat_for_nested_array_values_when_available() -> TestResult {
        assert_structural_ffi_matches_compat_when_available(br#"{"alg":"HS256","crit":["exp"]}"#)
    }

    #[test]
    fn structural_ffi_matches_compat_for_nested_object_values_when_available() -> TestResult {
        assert_structural_ffi_matches_compat_when_available(
            br#"{"alg":"HS256","epk":{"kty":"EC"}}"#,
        )
    }

    #[test]
    fn structural_ffi_matches_compat_internal_error_for_non_object_shape_when_available(
    ) -> TestResult {
        assert_structural_ffi_matches_compat_internal_error_when_available(br#"["alg","HS256"]"#)
    }

    #[test]
    fn structural_ffi_matches_compat_internal_error_for_invalid_json_when_available() -> TestResult
    {
        assert_structural_ffi_matches_compat_internal_error_when_available(br#"{"alg":"HS256""#)
    }

    #[test]
    fn structural_ffi_matches_compat_internal_error_for_control_char_in_key_when_available(
    ) -> TestResult {
        assert_structural_ffi_matches_compat_internal_error_when_available(b"{\"al\ng\":\"HS256\"}")
    }

    #[test]
    fn parse_rejects_non_ascii_keys() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let result = parse_json_header_lowstar(br#"{"\u00e5lg":"HS256"}"#);
        if result != Err(JsonError::ParserUnavailable) {
            assert_eq!(
                result,
                Err(JsonError::InvalidKeyEncoding(
                    JoseHeaderParseError::NonAsciiKey.to_string()
                ))
            );
        }
        Ok(())
    }

    #[test]
    fn parse_rejects_trailing_bytes() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let result = parse_json_header_lowstar(br#"{"alg":"HS256"}x"#);
        if result != Err(JsonError::ParserUnavailable) {
            assert_eq!(
                result,
                Err(JsonError::TrailingBytes(
                    "trailing bytes after JOSE header JSON object".to_string()
                ))
            );
        }
        Ok(())
    }

    #[test]
    fn lowstar_entries_reject_non_utf8_keys_like_tlv() -> TestResult {
        skip_if_lowstar_unavailable!();
        let key = CString::new(vec![0xff])?;
        let value = CString::new("HS256")?;
        let members = [JsonMemberC {
            key_buf: key.as_ptr().cast::<u8>(),
            key_len: u32::try_from(key.as_bytes().len())?,
            value_kind: JSON_VALUE_STRING,
            padding: [0; 3],
            value_buf: value.as_ptr().cast::<u8>(),
            value_len: u32::try_from(value.as_bytes().len())?,
        }];

        assert_eq!(
            ::ffi::parse_json_entries_safe(&members),
            Err(JsonError::InvalidKeyEncoding(
                JoseHeaderParseError::NonUtf8Key.to_string()
            ))
        );
        Ok(())
    }

    #[test]
    fn lowstar_entries_reject_non_utf8_values_like_tlv() -> TestResult {
        skip_if_lowstar_unavailable!();
        let key = CString::new("alg")?;
        let value = CString::new(vec![0xff])?;
        let members = [JsonMemberC {
            key_buf: key.as_ptr().cast::<u8>(),
            key_len: u32::try_from(key.as_bytes().len())?,
            value_kind: JSON_VALUE_STRING,
            padding: [0; 3],
            value_buf: value.as_ptr().cast::<u8>(),
            value_len: u32::try_from(value.as_bytes().len())?,
        }];

        assert_eq!(
            ::ffi::parse_json_entries_safe(&members),
            Err(JsonError::InvalidValueUtf8(
                JoseHeaderParseError::NonUtf8Value.to_string()
            ))
        );
        Ok(())
    }

    #[test]
    fn parse_rejects_non_object() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let json = br#"["alg","HS256"]"#;
        let result = parse_json_header_lowstar(json);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn parse_rejects_invalid_json() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let json = br#"{"alg":"HS256""#; // missing closing brace
        let result = parse_json_header_lowstar(json);
        assert!(result.is_err());
        Ok(())
    }
}

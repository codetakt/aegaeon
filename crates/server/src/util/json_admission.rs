use aegaeon_jose::jwt::{JwtClaims, JwtClaimsDecodeError};
#[cfg(test)]
use aegaeon_jose::raw_json::RawJsonBackend;
use aegaeon_jose::raw_json::{self, RawJsonObjectError, RawJsonSurface};
use base64::Engine;
use serde::de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use std::collections::HashSet;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonObjectParseError {
    BackendPolicy,
    InvalidJson,
    TrailingBytes,
    DuplicateKey,
    InvalidShape,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonAdmissionError {
    InvalidJson,
    TrailingBytes,
    DuplicateKey,
}

impl fmt::Display for JsonAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson => f.write_str("invalid JSON"),
            Self::TrailingBytes => f.write_str("trailing bytes after JSON"),
            Self::DuplicateKey => f.write_str("duplicate JSON object key"),
        }
    }
}

impl std::error::Error for JsonAdmissionError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedAssertionClaimsError {
    VerificationFailed,
    ClaimsInvalid,
    BackendPolicy,
}

const DUPLICATE_JSON_OBJECT_KEY_ERROR: &str = "duplicate JSON object key";

/// Recursively validate JSON while rejecting duplicate object members.
///
/// This is intentionally shape-agnostic: callers may admit objects, arrays, or
/// scalars, then apply their own typed decode / semantic validation after the
/// duplicate-key gate has closed.
///
/// # Errors
///
/// Returns `JsonAdmissionError` when the payload is invalid JSON, has trailing
/// bytes, or contains duplicate object keys at any depth.
pub fn validate_json_without_duplicate_object_keys(bytes: &[u8]) -> Result<(), JsonAdmissionError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    NoDuplicateJsonSeed
        .deserialize(&mut deserializer)
        .map_err(|err| {
            if err.to_string().contains(DUPLICATE_JSON_OBJECT_KEY_ERROR) {
                JsonAdmissionError::DuplicateKey
            } else {
                JsonAdmissionError::InvalidJson
            }
        })?;
    deserializer
        .end()
        .map_err(|_| JsonAdmissionError::TrailingBytes)
}

/// Deserialize JSON after recursive duplicate-key admission.
///
/// # Errors
///
/// Returns `JsonAdmissionError` when admission fails or when typed
/// deserialization rejects the admitted payload shape.
pub fn deserialize_json_without_duplicate_object_keys<T: DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, JsonAdmissionError> {
    validate_json_without_duplicate_object_keys(bytes)?;
    serde_json::from_slice(bytes).map_err(|_| JsonAdmissionError::InvalidJson)
}

struct NoDuplicateJsonSeed;

impl<'de> DeserializeSeed<'de> for NoDuplicateJsonSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateJsonVisitor)
    }
}

struct NoDuplicateJsonVisitor;

impl<'de> Visitor<'de> for NoDuplicateJsonVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        NoDuplicateJsonSeed.deserialize(deserializer)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while seq.next_element_seed(NoDuplicateJsonSeed)?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(de::Error::custom(DUPLICATE_JSON_OBJECT_KEY_ERROR));
            }
            map.next_value_seed(NoDuplicateJsonSeed)?;
        }
        Ok(())
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct JwtValidationProbe {
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jti: Option<String>,
}

#[must_use]
pub fn decode_compact_jwt_payload(token: &str) -> Option<Vec<u8>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()
}

/// Verify a signed JWT assertion with `jsonwebtoken` and then decode the
/// registered claims through the per-surface raw JSON gate.
///
/// The initial `jsonwebtoken` decode is intentionally narrow and is used only
/// for signature / registered-claim validation. Duplicate-key rejection and
/// top-level claim-shape validation remain authoritative in the surface-aware
/// raw JSON decoder.
///
/// # Errors
///
/// Returns [`SignedAssertionClaimsError::VerificationFailed`] when compact-JWT
/// verification fails, [`SignedAssertionClaimsError::ClaimsInvalid`] when the
/// admitted payload violates the selected raw JSON surface shape, and
/// [`SignedAssertionClaimsError::BackendPolicy`] when the server raw JSON
/// backend policy is misconfigured.
pub fn verify_signed_assertion_registered_claims(
    assertion: &str,
    decoding_key: &jsonwebtoken::DecodingKey,
    validation: &jsonwebtoken::Validation,
    surface: RawJsonSurface,
) -> Result<JwtClaims, SignedAssertionClaimsError> {
    jsonwebtoken::decode::<JwtValidationProbe>(assertion, decoding_key, validation)
        .map_err(|_| SignedAssertionClaimsError::VerificationFailed)?;
    let payload = decode_compact_jwt_payload(assertion)
        .ok_or(SignedAssertionClaimsError::VerificationFailed)?;
    JwtClaims::decode_registered_claims_for_surface(surface, &payload)
        .map_err(|err| signed_assertion_claims_error_from_jwt_claims_decode(&err))
}

pub(crate) fn signed_assertion_claims_error_from_jwt_claims_decode(
    err: &JwtClaimsDecodeError,
) -> SignedAssertionClaimsError {
    match err {
        JwtClaimsDecodeError::RawJson(RawJsonObjectError::InvalidBackendPolicy(_)) => {
            SignedAssertionClaimsError::BackendPolicy
        }
        JwtClaimsDecodeError::RawJson(
            RawJsonObjectError::DuplicateKey
            | RawJsonObjectError::InvalidJson(_)
            | RawJsonObjectError::TrailingBytes(_)
            | RawJsonObjectError::InvalidShape(_),
        )
        | JwtClaimsDecodeError::InvalidShape => SignedAssertionClaimsError::ClaimsInvalid,
    }
}

fn map_raw_json_object_error(err: &RawJsonObjectError) -> JsonObjectParseError {
    match err {
        RawJsonObjectError::InvalidBackendPolicy(_) => JsonObjectParseError::BackendPolicy,
        RawJsonObjectError::DuplicateKey => JsonObjectParseError::DuplicateKey,
        RawJsonObjectError::InvalidJson(_) => JsonObjectParseError::InvalidJson,
        RawJsonObjectError::TrailingBytes(_) => JsonObjectParseError::TrailingBytes,
        RawJsonObjectError::InvalidShape(_) => JsonObjectParseError::InvalidShape,
    }
}

/// Deserialize a JSON object on the compat semantic-decode path while
/// rejecting duplicate object keys for a specific raw-admission surface.
///
/// # Errors
///
/// Returns `JsonObjectParseError` when the payload is not valid JSON, is not a
/// JSON object matching `T`, contains duplicate keys, or the selected surface
/// requests an unsupported backend policy.
pub(crate) fn deserialize_compat_json_object_without_duplicate_keys_result_for_surface<
    T: DeserializeOwned,
>(
    surface: RawJsonSurface,
    payload: &[u8],
) -> Result<T, JsonObjectParseError> {
    match raw_json::deserialize_compat_json_object_without_duplicate_keys_with_report_for_surface(
        surface, payload,
    ) {
        Ok(report) => Ok(report.value),
        Err(err) => Err(map_raw_json_object_error(&err)),
    }
}

/// Deserialize a JSON object on the compat semantic-decode path while
/// rejecting duplicate keys with an explicit caller-selected raw JSON backend
/// for the given surface.
///
/// # Errors
///
/// Returns `JsonObjectParseError` when the payload is not valid JSON, is not a
/// JSON object matching `T`, or contains duplicate keys.
#[cfg(test)]
pub(crate) fn deserialize_compat_json_object_without_duplicate_keys_result_with_backend_for_surface<
    T: DeserializeOwned,
>(
    surface: RawJsonSurface,
    backend: RawJsonBackend,
    payload: &[u8],
) -> Result<T, JsonObjectParseError> {
    match raw_json::deserialize_compat_json_object_without_duplicate_keys_with_report_for_surface_and_backend(surface, backend, payload) {
        Ok(report) => Ok(report.value),
        Err(err) => Err(map_raw_json_object_error(&err)),
    }
}

/// Decode the protected header from a compact JWT after JOSE-header raw JSON admission.
///
/// The returned header has passed the source-managed `jose-header` surface, so
/// duplicate protected-header members fail closed before `alg` / `kid` drive
/// key selection or algorithm policy.
///
/// # Errors
///
/// Returns `JsonObjectParseError` when the compact form is malformed, the
/// header segment is not valid base64url JSON, the raw-JSON backend policy is
/// unavailable, or duplicate/invalid object members are present.
#[cfg(test)]
pub fn decode_compact_jwt_header_without_duplicate_keys(
    token: &str,
) -> Result<jsonwebtoken::Header, JsonObjectParseError> {
    #[allow(deprecated)]
    decode_compact_jwt_header_without_duplicate_keys_with_max_len(
        token,
        aegaeon_jose::policy::header_max_len(),
    )
}

pub fn decode_compact_jwt_header_without_duplicate_keys_with_max_len(
    token: &str,
    jose_header_max_len: usize,
) -> Result<jsonwebtoken::Header, JsonObjectParseError> {
    let header_bytes = decode_compact_jwt_header_bytes(token, jose_header_max_len)?;
    deserialize_compat_json_object_without_duplicate_keys_result_for_surface(
        RawJsonSurface::JoseHeader,
        &header_bytes,
    )
}

#[cfg(test)]
pub(super) fn decode_compact_jwt_header_value_without_duplicate_keys(
    token: &str,
) -> Result<Value, JsonObjectParseError> {
    #[allow(deprecated)]
    decode_compact_jwt_header_value_without_duplicate_keys_with_max_len(
        token,
        aegaeon_jose::policy::header_max_len(),
    )
}

pub(super) fn decode_compact_jwt_header_value_without_duplicate_keys_with_max_len(
    token: &str,
    jose_header_max_len: usize,
) -> Result<Value, JsonObjectParseError> {
    let header_bytes = decode_compact_jwt_header_bytes(token, jose_header_max_len)?;
    // DPoP headers carry an embedded JWK object; consult the jose-header
    // backend policy, then use recursive admission that preserves nested JWKs.
    raw_json::backend_policy_for_surface(RawJsonSurface::JoseHeader)
        .map_err(|_| JsonObjectParseError::BackendPolicy)?;
    deserialize_json_without_duplicate_object_keys(&header_bytes).map_err(|err| match err {
        JsonAdmissionError::InvalidJson => JsonObjectParseError::InvalidJson,
        JsonAdmissionError::TrailingBytes => JsonObjectParseError::TrailingBytes,
        JsonAdmissionError::DuplicateKey => JsonObjectParseError::DuplicateKey,
    })
}

fn decode_compact_jwt_header_bytes(
    token: &str,
    jose_header_max_len: usize,
) -> Result<Vec<u8>, JsonObjectParseError> {
    let mut parts = token.split('.');
    let (Some(header), Some(_payload), Some(_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(JsonObjectParseError::InvalidJson);
    };
    if header.len() > jose_header_max_len {
        return Err(JsonObjectParseError::InvalidJson);
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header)
        .map_err(|_| JsonObjectParseError::InvalidJson)
}

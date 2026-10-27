//! Complete protected-header admission before consumer-specific projection.
//!
//! Admission does not verify a signature or trust any header-supplied key. The
//! original compact bytes remain the caller's cryptographic input.

use crate::json_lowstar::{JoseHeaderStringMember, JsonError};
use crate::raw_json::{self, RawJsonBackend, RawJsonBackendPolicyError, RawJsonSurface};
use ffi::raw_json_structural::{self, RawJsonStructuralValueKind};
use serde::Serialize;
use std::collections::HashSet;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HeaderAdmissionError {
    #[error(transparent)]
    BackendPolicy(#[from] RawJsonBackendPolicyError),
    #[error(transparent)]
    Json(#[from] JsonError),
}

impl HeaderAdmissionError {
    pub(crate) fn into_json_error(self) -> JsonError {
        match self {
            Self::BackendPolicy(error) => JsonError::Internal(error.to_string()),
            Self::Json(error) => error,
        }
    }
}

/// Selects consumed fields; `enc` is consumed only for JWE.
#[derive(Debug, Clone, Copy)]
pub enum ProtectedHeaderKind {
    Jws,
    Jwe,
}

/// Typed processing fields admitted from a complete protected JSON object.
///
/// Absence is distinct from JSON null: present consumed fields must be strings.
/// Required fields, algorithms and profile purposes still require verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdmittedProtectedHeader {
    #[serde(skip_serializing_if = "Option::is_none")]
    alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    typ: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cty: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enc: Option<String>,
}

impl AdmittedProtectedHeader {
    #[must_use]
    pub fn alg(&self) -> Option<&str> {
        self.alg.as_deref()
    }

    #[must_use]
    pub fn typ(&self) -> Option<&str> {
        self.typ.as_deref()
    }

    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// Project admitted processing fields for a third-party JWT consumer.
    /// Untrusted key hints are never included in the projection.
    ///
    /// # Errors
    /// Returns a JSON error for missing or unsupported third-party header fields.
    pub fn into_jwt_header(self) -> Result<jsonwebtoken::Header, serde_json::Error> {
        serde_json::from_value(serde_json::to_value(self)?)
    }

    pub(crate) fn normalize_pairs(self) -> Result<Vec<(String, String)>, JsonError> {
        let members = [
            ("alg", self.alg),
            ("typ", self.typ),
            ("kid", self.kid),
            ("cty", self.cty),
            ("enc", self.enc),
        ]
        .into_iter()
        .filter_map(|(key, value)| {
            value.map(|value| JoseHeaderStringMember {
                key: key.to_string(),
                value: Some(value),
            })
        })
        .collect();
        #[cfg(feature = "ffi_jose_header_tlv")]
        {
            crate::tlv::normalize_header_members_via_tlv_ffi(members)
        }
        #[cfg(not(feature = "ffi_jose_header_tlv"))]
        {
            crate::json_lowstar::normalize_header_members_lowstar(members)
        }
    }
}

/// Admit a complete protected header using the configured JOSE structural parser.
///
/// No critical extension, unencoded payload or compression is supported. Unknown
/// noncritical members are ignored only after structural and duplicate checks.
/// Callers must enforce their encoded-header size bound before base64 decoding.
///
/// # Errors
/// Rejects unavailable/invalid parser policy, malformed JSON, decoded duplicate
/// names, wrong consumed types, and any presence of `crit`, `b64` or `zip`.
pub fn admit_protected_header(
    bytes: &[u8],
    kind: ProtectedHeaderKind,
) -> Result<AdmittedProtectedHeader, HeaderAdmissionError> {
    admit_for_surface(bytes, kind, RawJsonSurface::JoseHeader)
}

/// Admit a JWT access header with its distinct configured structural surface.
///
/// # Errors
/// Returns the same semantic errors as [`admit_protected_header`], while retaining
/// the `JwtAccessTokenHeader` backend policy rather than the JOSE-header policy.
pub fn admit_jwt_access_token_header(
    bytes: &[u8],
) -> Result<AdmittedProtectedHeader, HeaderAdmissionError> {
    admit_for_surface(
        bytes,
        ProtectedHeaderKind::Jws,
        RawJsonSurface::JwtAccessTokenHeader,
    )
}

fn admit_for_surface(
    bytes: &[u8],
    kind: ProtectedHeaderKind,
    surface: RawJsonSurface,
) -> Result<AdmittedProtectedHeader, HeaderAdmissionError> {
    let policy = raw_json::backend_policy_for_surface(surface)?;
    if policy.backend != RawJsonBackend::VerifiedStructuralV1 {
        return Err(JsonError::ParserUnavailable.into());
    }
    admit_parsed_header(
        bytes,
        kind,
        raw_json_structural::parse_raw_json_structural(bytes),
    )
}

fn admit_parsed_header(
    bytes: &[u8],
    kind: ProtectedHeaderKind,
    parsed: Result<
        raw_json_structural::RawJsonStructuralParseResult,
        raw_json_structural::RawJsonStructuralParseError,
    >,
) -> Result<AdmittedProtectedHeader, HeaderAdmissionError> {
    let parsed = parsed.map_err(crate::json_lowstar::map_structural_parse_error_to_json_error)?;
    if parsed.has_trailing_bytes(bytes) {
        return Err(JsonError::TrailingBytes(
            "trailing bytes after JOSE header JSON object".into(),
        )
        .into());
    }
    let mut admitted = AdmittedProtectedHeader {
        alg: None,
        typ: None,
        kid: None,
        cty: None,
        enc: None,
    };
    let mut seen = HashSet::with_capacity(parsed.members.len());
    for member in &parsed.members {
        let key = crate::json_lowstar::decode_structural_key_bytes(&member.key)?;
        if !seen.insert(key.clone()) {
            return Err(JsonError::PolicyViolation("duplicate-key".into()).into());
        }
        let field = match key.as_str() {
            "crit" | "b64" | "zip" => {
                return Err(JsonError::PolicyViolation(format!("unsupported-header:{key}")).into());
            }
            "alg" => &mut admitted.alg,
            "typ" => &mut admitted.typ,
            "kid" => &mut admitted.kid,
            "cty" => &mut admitted.cty,
            "enc" if matches!(kind, ProtectedHeaderKind::Jwe) => &mut admitted.enc,
            _ => continue,
        };
        if member.value_kind != RawJsonStructuralValueKind::String {
            return Err(JsonError::PolicyViolation(format!("header-string-required:{key}")).into());
        }
        let value = member
            .value_slice(bytes)
            .ok_or_else(|| JsonError::Internal("header value span out of bounds".into()))?;
        *field = Some(
            serde_json::from_slice(value)
                .map_err(|_| JsonError::Internal("invalid header string".into()))?,
        );
    }
    Ok(admitted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_admission_parser_unavailable_never_falls_back() {
        for bytes in [
            br#"{"alg":"HS256"}"#.as_slice(),
            br#"{"alg":"HS256","alg":"RS256"}"#,
        ] {
            assert!(matches!(
                admit_parsed_header(
                    bytes,
                    ProtectedHeaderKind::Jws,
                    Err(raw_json_structural::RawJsonStructuralParseError::ParserUnavailable)
                ),
                Err(HeaderAdmissionError::Json(JsonError::ParserUnavailable))
            ));
        }
    }

    struct EnvRestore(&'static str, Option<std::ffi::OsString>);
    impl EnvRestore {
        fn set(key: &'static str, value: &str) -> Self {
            let saved = Self(key, std::env::var_os(key));
            std::env::set_var(key, value);
            saved
        }
    }
    impl Drop for EnvRestore {
        fn drop(&mut self) {
            if let Some(value) = &self.1 {
                std::env::set_var(self.0, value);
            } else {
                std::env::remove_var(self.0);
            }
        }
    }

    #[test]
    fn common_admission_invalid_policy_and_distinct_access_surface() {
        let _guard = raw_json::RAW_JSON_TEST_ENV_GUARD
            .lock()
            .expect("raw json env guard");
        let bytes = br#"{"alg":"HS256"}"#;
        let _jose = EnvRestore::set("AEGAEON_RAW_JSON_BACKEND_JOSE_HEADER", "invalid");
        let _access = EnvRestore::set(
            "AEGAEON_RAW_JSON_BACKEND_JWT_ACCESS_TOKEN_HEADER",
            "verified-structural-v1",
        );
        assert!(matches!(
            admit_protected_header(bytes, ProtectedHeaderKind::Jws),
            Err(HeaderAdmissionError::BackendPolicy(_))
        ));
        assert!(admit_jwt_access_token_header(bytes).is_ok());
        let _jose_valid = EnvRestore::set(
            "AEGAEON_RAW_JSON_BACKEND_JOSE_HEADER",
            "verified-structural-v1",
        );
        let _access_invalid = EnvRestore::set(
            "AEGAEON_RAW_JSON_BACKEND_JWT_ACCESS_TOKEN_HEADER",
            "invalid",
        );
        assert!(admit_protected_header(bytes, ProtectedHeaderKind::Jws).is_ok());
        assert!(matches!(
            admit_jwt_access_token_header(bytes),
            Err(HeaderAdmissionError::BackendPolicy(_))
        ));
        let _compat = EnvRestore::set("AEGAEON_RAW_JSON_BACKEND_JOSE_HEADER", "serde-compat");
        assert!(matches!(
            admit_protected_header(bytes, ProtectedHeaderKind::Jws),
            Err(HeaderAdmissionError::Json(JsonError::ParserUnavailable))
        ));
    }
}

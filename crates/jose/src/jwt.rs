// JWT (JSON Web Token) implementation placeholder

use crate::raw_json::{self, RawJsonObjectError, RawJsonSurface};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(flatten, default = "empty_custom")]
    pub custom: Value,
}

#[allow(dead_code)]
fn empty_custom() -> Value {
    Value::Object(Map::new())
}

// These flags are orthogonal protocol requirements rather than latent state,
// so a compact boolean configuration is intentional here.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct ValidationContext {
    pub now: i64,
    pub leeway: Duration,
    pub expected_issuer: Option<String>,
    pub expected_subject: Option<String>,
    pub allowed_audiences: Option<Vec<String>>,
    pub require_issuer: bool,
    pub require_subject: bool,
    pub require_audience: bool,
    pub require_exp: bool,
    pub require_jti: bool,
    pub require_iat: bool,
}

impl ValidationContext {
    #[must_use]
    pub fn builder() -> ValidationContextBuilder {
        ValidationContextBuilder::default()
    }
}

impl Default for ValidationContext {
    fn default() -> Self {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();
        let now = i64::try_from(now_secs).unwrap_or(i64::MAX);
        Self {
            now,
            leeway: Duration::from_secs(0),
            expected_issuer: None,
            expected_subject: None,
            allowed_audiences: None,
            require_issuer: false,
            require_subject: false,
            require_audience: false,
            require_exp: true,
            require_jti: false,
            require_iat: false,
        }
    }
}

#[derive(Debug, Default)]
pub struct ValidationContextBuilder {
    inner: ValidationContext,
}

impl ValidationContextBuilder {
    #[must_use]
    pub fn now(mut self, now: i64) -> Self {
        self.inner.now = now;
        self
    }

    #[must_use]
    pub fn leeway(mut self, leeway: Duration) -> Self {
        self.inner.leeway = leeway;
        self
    }

    #[must_use]
    pub fn expected_issuer<I: Into<String>>(mut self, issuer: I) -> Self {
        self.inner.expected_issuer = Some(issuer.into());
        self
    }

    #[must_use]
    pub fn expected_subject<S: Into<String>>(mut self, subject: S) -> Self {
        self.inner.expected_subject = Some(subject.into());
        self
    }

    #[must_use]
    pub fn allowed_audiences<A: Into<String>>(
        mut self,
        audiences: impl IntoIterator<Item = A>,
    ) -> Self {
        self.inner.allowed_audiences = Some(audiences.into_iter().map(Into::into).collect());
        self
    }

    #[must_use]
    pub fn require_issuer(mut self, required: bool) -> Self {
        self.inner.require_issuer = required;
        self
    }

    #[must_use]
    pub fn require_subject(mut self, required: bool) -> Self {
        self.inner.require_subject = required;
        self
    }

    #[must_use]
    pub fn require_audience(mut self, required: bool) -> Self {
        self.inner.require_audience = required;
        self
    }

    #[must_use]
    pub fn require_exp(mut self, required: bool) -> Self {
        self.inner.require_exp = required;
        self
    }

    #[must_use]
    pub fn require_jti(mut self, required: bool) -> Self {
        self.inner.require_jti = required;
        self
    }

    #[must_use]
    pub fn require_iat(mut self, required: bool) -> Self {
        self.inner.require_iat = required;
        self
    }

    #[must_use]
    pub fn build(self) -> ValidationContext {
        self.inner
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum JwtValidationError {
    #[error("missing claim: {0}")]
    MissingClaim(&'static str),
    #[error("issuer mismatch")]
    IssuerMismatch,
    #[error("subject mismatch")]
    SubjectMismatch,
    #[error("audience mismatch")]
    AudienceMismatch,
    #[error("invalid audience format")]
    InvalidAudienceFormat,
    #[error("token expired")]
    Expired,
    #[error("token not yet valid")]
    NotYetValid,
    #[error("issued at is in the future")]
    IssuedAtInFuture,
    #[error("temporal claim arithmetic overflow")]
    TemporalOverflow,
}

pub type JwtValidationResult<T> = Result<T, JwtValidationError>;

#[derive(Debug, Error)]
pub enum JwtClaimsDecodeError {
    #[error(transparent)]
    RawJson(#[from] RawJsonObjectError),
    #[error("invalid registered JWT claim shape")]
    InvalidShape,
}

impl JwtClaims {
    /// Decode RFC 7519 registered claims for a specific raw JSON admission surface.
    ///
    /// This decoder is intentionally surface-aware so every JWT-family caller
    /// shares the same duplicate-key and claim-shape checks while keeping
    /// surface-specific policy validation separate.
    ///
    /// # Errors
    ///
    /// Returns [`JwtClaimsDecodeError`] when the payload is not a valid JSON
    /// object for the selected surface, contains duplicate top-level keys, or
    /// any registered claim has the wrong JSON shape.
    pub fn decode_registered_claims_for_surface(
        surface: RawJsonSurface,
        payload: &[u8],
    ) -> Result<Self, JwtClaimsDecodeError> {
        let report = raw_json::parse_json_object_members_with_report_for_surface(surface, payload)?;
        Self::decode_registered_claims_from_members(report.value)
    }

    #[cfg(test)]
    fn decode_registered_claims_for_surface_and_backend(
        surface: RawJsonSurface,
        backend: raw_json::RawJsonBackend,
        payload: &[u8],
    ) -> Result<Self, JwtClaimsDecodeError> {
        let report = raw_json::parse_json_object_members_with_backend_for_surface(
            surface, backend, payload,
        )?;
        Self::decode_registered_claims_from_members(report.value)
    }

    fn decode_registered_claims_from_members(
        members: Vec<raw_json::RawJsonObjectMember>,
    ) -> Result<Self, JwtClaimsDecodeError> {
        raw_json::ensure_unique_object_keys(&members)?;
        let mut claims = Self {
            iss: None,
            sub: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
            custom: Value::Object(Map::new()),
        };
        let mut custom = Map::new();

        for member in members {
            match member.key.as_str() {
                "iss" => claims.iss = parse_optional_string_claim(&member.value)?,
                "sub" => claims.sub = parse_optional_string_claim(&member.value)?,
                "aud" => claims.aud = parse_optional_audience_claim(&member.value)?,
                "exp" => claims.exp = parse_optional_i64_claim(&member.value)?,
                "nbf" => claims.nbf = parse_optional_i64_claim(&member.value)?,
                "iat" => claims.iat = parse_optional_i64_claim(&member.value)?,
                "jti" => claims.jti = parse_optional_string_claim(&member.value)?,
                _ => {
                    custom.insert(member.key, member.value);
                }
            }
        }

        claims.custom = Value::Object(custom);
        Ok(claims)
    }

    /// Validate standard JWT claims against the supplied policy context.
    ///
    /// # Errors
    ///
    /// Returns [`JwtValidationError`] when a required claim is missing, issuer /
    /// subject / audience expectations do not match, or temporal claims violate
    /// the configured validation window.
    pub fn validate(&self, ctx: &ValidationContext) -> JwtValidationResult<()> {
        if ctx.require_issuer && self.iss.is_none() {
            return Err(JwtValidationError::MissingClaim("iss"));
        }
        if let Some(expected) = &ctx.expected_issuer {
            match self.iss.as_deref() {
                Some(actual) if actual == expected => {}
                Some(_) => return Err(JwtValidationError::IssuerMismatch),
                None => return Err(JwtValidationError::MissingClaim("iss")),
            }
        }

        if ctx.require_subject && self.sub.is_none() {
            return Err(JwtValidationError::MissingClaim("sub"));
        }
        if let Some(expected_subject) = &ctx.expected_subject {
            match self.sub.as_deref() {
                Some(actual) if actual == expected_subject => {}
                Some(_) => return Err(JwtValidationError::SubjectMismatch),
                None => return Err(JwtValidationError::MissingClaim("sub")),
            }
        }

        let audiences = self.aud.as_ref().map(parse_audience_claim).transpose()?;

        if let Some(expected) = &ctx.allowed_audiences {
            let auds = audiences
                .as_ref()
                .ok_or(JwtValidationError::MissingClaim("aud"))?;
            if expected.is_empty()
                || !auds
                    .iter()
                    .any(|aud| expected.iter().any(|expected_aud| expected_aud == aud))
            {
                return Err(JwtValidationError::AudienceMismatch);
            }
        }
        if ctx.require_audience && audiences.as_ref().is_none_or(Vec::is_empty) {
            return Err(JwtValidationError::MissingClaim("aud"));
        }

        let leeway = i64::try_from(ctx.leeway.as_secs())
            .map_err(|_| JwtValidationError::TemporalOverflow)?;

        if let Some(exp) = self.exp {
            let exp_with_leeway = exp
                .checked_add(leeway)
                .ok_or(JwtValidationError::TemporalOverflow)?;
            if ctx.now > exp_with_leeway {
                return Err(JwtValidationError::Expired);
            }
        } else if ctx.require_exp {
            return Err(JwtValidationError::MissingClaim("exp"));
        }

        if let Some(nbf) = self.nbf {
            let now_with_leeway = ctx
                .now
                .checked_add(leeway)
                .ok_or(JwtValidationError::TemporalOverflow)?;
            if now_with_leeway < nbf {
                return Err(JwtValidationError::NotYetValid);
            }
        }

        if let Some(iat) = self.iat {
            let now_with_leeway = ctx
                .now
                .checked_add(leeway)
                .ok_or(JwtValidationError::TemporalOverflow)?;
            if now_with_leeway < iat {
                return Err(JwtValidationError::IssuedAtInFuture);
            }
        } else if ctx.require_iat {
            return Err(JwtValidationError::MissingClaim("iat"));
        }

        if ctx.require_jti && self.jti.is_none() {
            return Err(JwtValidationError::MissingClaim("jti"));
        }

        Ok(())
    }
}

fn parse_audience_claim(value: &Value) -> JwtValidationResult<Vec<&str>> {
    match value {
        Value::String(s) => Ok(vec![s.as_str()]),
        Value::Array(arr) => {
            let mut result = Vec::with_capacity(arr.len());
            for item in arr {
                if let Value::String(s) = item {
                    result.push(s.as_str());
                } else {
                    return Err(JwtValidationError::InvalidAudienceFormat);
                }
            }
            Ok(result)
        }
        Value::Null => Ok(Vec::new()),
        _ => Err(JwtValidationError::InvalidAudienceFormat),
    }
}

fn parse_optional_string_claim(value: &Value) -> Result<Option<String>, JwtClaimsDecodeError> {
    match value {
        Value::Null => Ok(None),
        Value::String(value) => Ok(Some(value.clone())),
        _ => Err(JwtClaimsDecodeError::InvalidShape),
    }
}

fn parse_optional_i64_claim(value: &Value) -> Result<Option<i64>, JwtClaimsDecodeError> {
    match value {
        Value::Null => Ok(None),
        Value::Number(value) => value
            .as_i64()
            .map(Some)
            .ok_or(JwtClaimsDecodeError::InvalidShape),
        _ => Err(JwtClaimsDecodeError::InvalidShape),
    }
}

fn parse_optional_audience_claim(value: &Value) -> Result<Option<Value>, JwtClaimsDecodeError> {
    match value {
        Value::Null => Ok(None),
        Value::String(value) => Ok(Some(Value::String(value.clone()))),
        Value::Array(values) => {
            let mut audience = Vec::with_capacity(values.len());
            for value in values {
                let Value::String(value) = value else {
                    return Err(JwtClaimsDecodeError::InvalidShape);
                };
                audience.push(Value::String(value.clone()));
            }
            Ok(Some(Value::Array(audience)))
        }
        _ => Err(JwtClaimsDecodeError::InvalidShape),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_registered_claims_rejects_duplicate_keys() {
        let err = JwtClaims::decode_registered_claims_for_surface_and_backend(
            RawJsonSurface::PrivateKeyJwtPayload,
            raw_json::RawJsonBackend::SerdeCompat,
            br#"{"iss":"issuer","iss":"evil","sub":"subject"}"#,
        )
        .expect_err("duplicate registered claims must fail closed");

        assert!(matches!(
            err,
            JwtClaimsDecodeError::RawJson(RawJsonObjectError::DuplicateKey)
        ));
    }

    #[test]
    fn decode_registered_claims_preserves_custom_members() {
        let claims = JwtClaims::decode_registered_claims_for_surface_and_backend(
            RawJsonSurface::SoftwareStatement,
            raw_json::RawJsonBackend::SerdeCompat,
            br#"{"iss":"issuer","sub":"subject","aud":["one","two"],"exp":42,"software_id":"abc"}"#,
        )
        .expect("valid registered claims should decode");

        assert_eq!(claims.iss.as_deref(), Some("issuer"));
        assert_eq!(claims.sub.as_deref(), Some("subject"));
        assert_eq!(
            claims.aud,
            Some(Value::Array(vec![
                Value::String("one".to_string()),
                Value::String("two".to_string()),
            ]))
        );
        assert_eq!(claims.exp, Some(42));
        assert_eq!(
            claims.custom,
            Value::Object(Map::from_iter([(
                "software_id".to_string(),
                Value::String("abc".to_string()),
            )]))
        );
    }

    #[test]
    fn decode_registered_claims_rejects_invalid_audience_shape() {
        let err = JwtClaims::decode_registered_claims_for_surface_and_backend(
            RawJsonSurface::JwtBearerAssertionPayload,
            raw_json::RawJsonBackend::SerdeCompat,
            br#"{"iss":"issuer","sub":"subject","aud":[1]}"#,
        )
        .expect_err("non-string audience array members must fail closed");

        assert!(matches!(err, JwtClaimsDecodeError::InvalidShape));
    }

    #[test]
    fn decode_registered_claims_rejects_non_numeric_dates() {
        for claims in [
            br#"{"exp":"abc"}"#.as_slice(),
            br#"{"nbf":"abc"}"#.as_slice(),
            br#"{"iat":"abc"}"#.as_slice(),
        ] {
            let err = JwtClaims::decode_registered_claims_for_surface_and_backend(
                RawJsonSurface::JwtBearerAssertionPayload,
                raw_json::RawJsonBackend::SerdeCompat,
                claims,
            )
            .expect_err("non-numeric NumericDate claim must fail closed");

            assert!(matches!(err, JwtClaimsDecodeError::InvalidShape));
        }
    }
}

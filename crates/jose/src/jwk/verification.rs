use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;

use super::{Jwk, JwkError, JwkSet, KeyMaterial};

const RSA_ALGORITHMS: &[&str] = &["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"];

fn component(value: &str, max_bytes: usize) -> Option<Vec<u8>> {
    if value.is_empty() || value.len() > (max_bytes * 4).div_ceil(3) {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    (!bytes.is_empty() && bytes.len() <= max_bytes && URL_SAFE_NO_PAD.encode(&bytes) == value)
        .then_some(bytes)
}

impl Jwk {
    /// Material-compatible signature algorithms, including any exact declared restriction.
    /// Returns no algorithms for malformed, unsupported or ineligible public fields.
    /// This revalidates typed keys that callers constructed or mutated themselves.
    #[must_use]
    pub fn verification_algorithms(&self) -> Vec<&'static str> {
        if !self.is_signature_capable() {
            return Vec::new();
        }
        let compatible = match (&*self.key_type, &self.material) {
            ("RSA", KeyMaterial::Rsa { n, e }) => {
                let Some(n) = component(n, 2048) else {
                    return Vec::new();
                };
                let Some(e) = component(e, 5) else {
                    return Vec::new();
                };
                if aegaeon_crypto::public_key::validate_rsa_verification_components(&n, &e).is_err()
                {
                    return Vec::new();
                }
                RSA_ALGORITHMS
            }
            ("EC", KeyMaterial::Ec { crv, x, y }) => {
                let (width, algorithms): (usize, &[&'static str]) = match crv.as_str() {
                    "P-256" => (32, &["ES256"]),
                    "P-384" => (48, &["ES384"]),
                    _ => return Vec::new(),
                };
                let Some(x) = component(x, width) else {
                    return Vec::new();
                };
                let Some(y) = component(y, width) else {
                    return Vec::new();
                };
                if x.len() != width || y.len() != width {
                    return Vec::new();
                }
                let mut point = Vec::with_capacity(1 + 2 * width);
                point.push(4);
                point.extend_from_slice(&x);
                point.extend_from_slice(&y);
                if aegaeon_crypto::public_key::validate_ec_verification_point(crv, &point).is_err()
                {
                    return Vec::new();
                }
                algorithms
            }
            _ => return Vec::new(),
        };
        compatible
            .iter()
            .copied()
            .filter(|algorithm| {
                self.alg
                    .as_deref()
                    .is_none_or(|declared| declared == *algorithm)
            })
            .collect()
    }

    /// Whether current typed fields describe a supported verification candidate.
    #[must_use]
    pub fn is_verification_candidate(&self) -> bool {
        !self.verification_algorithms().is_empty()
    }
}

impl JwkSet {
    /// Admit supported public verification keys, ignoring unusable individual members.
    ///
    /// Original string kids remain observable and participate in uniqueness/profile
    /// checks even when their keys are rejected. Rejected key material is not retained.
    /// Admitted keys contain no uninterpreted extras. Raw-byte callers must reject
    /// duplicate object names and trailing bytes before constructing a `Value`.
    /// Empty or all-rejected sets are representable; consumers must refuse them.
    ///
    /// # Errors
    /// Returns an error for a malformed set envelope, not for an unusable member.
    pub fn from_verification_value(value: Value) -> Result<Self, JwkError> {
        let object = value.as_object().ok_or(JwkError::NotAnObject)?;
        let members = object
            .get("keys")
            .ok_or(JwkError::MissingField("keys"))?
            .as_array()
            .ok_or(JwkError::FieldNotStringArray { field: "keys" })?;
        let observed_kids = members
            .iter()
            .map(|member| member.get("kid").and_then(Value::as_str).map(str::to_owned))
            .collect();
        let keys = members
            .iter()
            .filter_map(|member| {
                let object = member.as_object()?;
                if ["kid", "alg"]
                    .iter()
                    .any(|name| object.get(*name).is_some_and(|v| !v.is_string()))
                {
                    return None;
                }
                let mut key = Jwk::from_value(member.clone()).ok()?;
                if !key.is_verification_candidate() {
                    return None;
                }
                key.extra.clear();
                Some(key)
            })
            .collect();
        Ok(Self {
            keys,
            observed_kids,
        })
    }

    /// Whether an original member declared this string kid, regardless of eligibility.
    #[must_use]
    pub fn observed_kid(&self, kid: &str) -> bool {
        self.observed_kids
            .iter()
            .any(|observed| observed.as_deref() == Some(kid))
    }

    /// Revalidate typed members before exposing verification candidates.
    pub fn verification_keys(&self) -> impl Iterator<Item = &Jwk> {
        self.keys
            .iter()
            .filter(|key| key.is_verification_candidate())
    }

    /// Select exactly one eligible key before narrowing by a token's algorithm.
    ///
    /// # Errors
    /// Returns an error for original-member duplicate string kids.
    pub fn select_verification_key(&self, kid: Option<&str>) -> Result<Option<&Jwk>, JwkError> {
        self.ensure_unique_kid()?;
        let mut candidates = self
            .verification_keys()
            .filter(|key| kid.is_none_or(|requested| key.kid() == Some(requested)));
        let selected = candidates.next();
        Ok(selected.filter(|_| candidates.next().is_none()))
    }
}

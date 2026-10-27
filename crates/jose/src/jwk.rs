use serde_json::{Map, Value};
use std::collections::HashSet;
use thiserror::Error;

mod usage;
mod verification;
pub use usage::verification_usage_allowed;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum JwkError {
    #[error("JWK must be a JSON object")]
    NotAnObject,
    #[error("missing field `{0}`")]
    MissingField(&'static str),
    #[error("field `{field}` must be a string")]
    FieldNotString { field: &'static str },
    #[error("field `{field}` must be an array of strings")]
    FieldNotStringArray { field: &'static str },
    #[error("unsupported key type `{0}`")]
    UnsupportedKeyType(String),
    #[error("duplicate key operation `{0}`")]
    DuplicateKeyOperation(String),
    #[error("use and key_ops contain contradictory known values")]
    InconsistentKeyUsage,
    #[error("duplicate kid `{0}`")]
    DuplicateKid(String),
    #[error("kid required but missing")]
    KidRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyUse {
    Signature,
    Encryption,
    Other(String),
}

impl KeyUse {
    fn from_str(value: &str) -> Self {
        match value {
            "sig" => KeyUse::Signature,
            "enc" => KeyUse::Encryption,
            other => KeyUse::Other(other.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeyMaterial {
    Rsa { n: String, e: String },
    Ec { crv: String, x: String, y: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jwk {
    pub key_type: String,
    pub key_use: Option<KeyUse>,
    pub key_ops: Option<Vec<String>>,
    pub kid: Option<String>,
    pub alg: Option<String>,
    pub material: KeyMaterial,
    pub extra: Map<String, Value>,
}

impl Jwk {
    /// Structurally parse a single JWK, preserving uninterpreted extra members.
    /// This does not establish cryptographic material validity.
    ///
    /// # Errors
    ///
    /// Returns [`JwkError`] if the value is not a JSON object, required fields
    /// are missing, field types do not match the JWK schema, or the key type is
    /// unsupported.
    pub fn from_value(value: Value) -> Result<Self, JwkError> {
        let Value::Object(mut obj) = value else {
            return Err(JwkError::NotAnObject);
        };

        let kty = expect_string(&mut obj, "kty")?.ok_or(JwkError::MissingField("kty"))?;
        let kid = expect_string(&mut obj, "kid")?;
        let alg = expect_string(&mut obj, "alg")?;
        let use_param = match obj.remove("use") {
            None => None,
            Some(Value::String(value)) => Some(value),
            Some(_) => return Err(JwkError::FieldNotString { field: "use" }),
        };
        let key_use = use_param.as_deref().map(KeyUse::from_str);

        let key_ops = match obj.remove("key_ops") {
            Some(Value::Array(arr)) => {
                let mut ops = Vec::with_capacity(arr.len());
                for item in arr {
                    if let Value::String(s) = item {
                        ops.push(s);
                    } else {
                        return Err(JwkError::FieldNotStringArray { field: "key_ops" });
                    }
                }
                Some(ops)
            }
            None => None,
            Some(other) => {
                obj.insert("key_ops".into(), other);
                return Err(JwkError::FieldNotStringArray { field: "key_ops" });
            }
        };

        usage::validate_key_usage(use_param.as_deref(), key_ops.as_deref())?;

        let material = match kty.as_str() {
            "RSA" => {
                let n = expect_string(&mut obj, "n")?.ok_or(JwkError::MissingField("n"))?;
                let e = expect_string(&mut obj, "e")?.ok_or(JwkError::MissingField("e"))?;
                KeyMaterial::Rsa { n, e }
            }
            "EC" => {
                let crv = expect_string(&mut obj, "crv")?.ok_or(JwkError::MissingField("crv"))?;
                let x = expect_string(&mut obj, "x")?.ok_or(JwkError::MissingField("x"))?;
                let y = expect_string(&mut obj, "y")?.ok_or(JwkError::MissingField("y"))?;
                KeyMaterial::Ec { crv, x, y }
            }
            other => return Err(JwkError::UnsupportedKeyType(other.to_string())),
        };

        Ok(Jwk {
            key_type: kty,
            key_use,
            key_ops,
            kid,
            alg,
            material,
            extra: obj,
        })
    }

    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// Whether this key's usage metadata permits signature verification.
    ///
    /// An absent use or exact `sig` is required. Present operations must be
    /// unique, contain `verify`, and contain only `sign` and/or `verify`.
    /// Algorithm and key-material validation remain the verifier's responsibility.
    #[must_use]
    pub fn is_signature_capable(&self) -> bool {
        let key_use = match self.key_use {
            None => None,
            Some(KeyUse::Signature) => Some("sig"),
            Some(KeyUse::Encryption | KeyUse::Other(_)) => return false,
        };
        verification_usage_allowed(key_use, self.key_ops.as_deref())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwkSet {
    keys: Vec<Jwk>,
    observed_kids: Vec<Option<String>>,
}

impl JwkSet {
    /// Structurally parse every member of a JWK set, failing on any invalid member.
    /// Use `from_verification_value` for tolerant material-admitted consumption.
    ///
    /// # Errors
    ///
    /// Returns [`JwkError`] if the value is not a JSON object, the `keys`
    /// member is missing or malformed, or any embedded JWK fails validation.
    pub fn from_value(value: Value) -> Result<Self, JwkError> {
        let Value::Object(obj) = value else {
            return Err(JwkError::NotAnObject);
        };
        let keys_value = obj
            .get("keys")
            .ok_or(JwkError::MissingField("keys"))?
            .as_array()
            .ok_or(JwkError::FieldNotStringArray { field: "keys" })?;

        let mut keys = Vec::with_capacity(keys_value.len());
        for item in keys_value {
            keys.push(Jwk::from_value(item.clone())?);
        }
        let observed_kids = keys.iter().map(|key| key.kid.clone()).collect();
        Ok(JwkSet {
            keys,
            observed_kids,
        })
    }

    #[must_use]
    pub fn keys(&self) -> &[Jwk] {
        &self.keys
    }

    /// Ensure all `kid` values in the set are unique.
    ///
    /// # Errors
    ///
    /// Returns [`JwkError::DuplicateKid`] if the same `kid` appears more than
    /// once in the set.
    pub fn ensure_unique_kid(&self) -> Result<(), JwkError> {
        let mut seen = HashSet::new();
        for kid in self.observed_kids.iter().flatten() {
            if !seen.insert(kid.clone()) {
                return Err(JwkError::DuplicateKid(kid.clone()));
            }
        }
        Ok(())
    }

    /// Ensure every JWK in the set has a `kid`.
    ///
    /// # Errors
    ///
    /// Returns [`JwkError::KidRequired`] if any key omits `kid`.
    pub fn ensure_all_have_kid(&self) -> Result<(), JwkError> {
        if self.observed_kids.iter().all(Option::is_some) {
            Ok(())
        } else {
            Err(JwkError::KidRequired)
        }
    }

    pub fn signature_keys(&self) -> impl Iterator<Item = &Jwk> {
        self.keys.iter().filter(|k| k.is_signature_capable())
    }
}

fn expect_string(
    map: &mut Map<String, Value>,
    key: &'static str,
) -> Result<Option<String>, JwkError> {
    match map.remove(key) {
        Some(Value::String(s)) => Ok(Some(s)),
        Some(Value::Null) | None => Ok(None),
        Some(other) => {
            map.insert(key.to_string(), other);
            Err(JwkError::FieldNotString { field: key })
        }
    }
}

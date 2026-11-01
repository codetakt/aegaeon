use aegaeon_jose::jwk::{Jwk, JwkSet, KeyMaterial, KeyUse};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use std::collections::HashMap;

use super::{FetchedJwk, FetchedJwks};
use crate::client_registry::jwks_validation::FetchedJwksValidationError;

impl<'de> Deserialize<'de> for FetchedJwks {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_value(&Value::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl FetchedJwks {
    pub(in crate::client_registry) fn from_value(
        value: &Value,
    ) -> Result<Self, FetchedJwksValidationError> {
        crate::client_registry::public_jwks::validate_public_client_jwks(value)
            .map_err(FetchedJwksValidationError::PublicClientPolicy)?;
        let set = JwkSet::from_verification_value(value.clone())
            .map_err(FetchedJwksValidationError::Parse)?;
        set.ensure_unique_kid()
            .map_err(FetchedJwksValidationError::DuplicateKid)?;
        let members = value
            .get("keys")
            .and_then(Value::as_array)
            .ok_or(FetchedJwksValidationError::NotJsonObject)?;
        let observed_kids = members
            .iter()
            .map(|member| member.get("kid").and_then(Value::as_str).map(str::to_owned))
            .collect();
        let mut legacy_fingerprints = legacy_fingerprints(members);
        let keys: Vec<_> = set.keys().iter().map(FetchedJwk::from).collect();
        // Keep every representable original fingerprint, including rejected
        // members. Unrelated malformed extras cannot remove an admitted key
        // from the reuse guard: use its validated public projection as fallback.
        for key in &keys {
            if let Some(kid) = &key.kid {
                legacy_fingerprints.entry(kid.clone()).or_insert_with(|| {
                    crate::client_registry::sha256_hex(
                        format!(
                            "{}|{}|{}|{}|{}",
                            key.kty,
                            key.n.as_deref().unwrap_or(""),
                            key.e.as_deref().unwrap_or(""),
                            key.x.as_deref().unwrap_or(""),
                            key.y.as_deref().unwrap_or("")
                        )
                        .as_bytes(),
                    )
                });
            }
        }
        Ok(Self {
            material_admitted: true,
            keys,
            observed_kids,
            legacy_fingerprints,
        })
    }

    pub(in crate::client_registry) fn legacy_fingerprints(&self) -> &HashMap<String, String> {
        &self.legacy_fingerprints
    }

    pub(in crate::client_registry) fn has_duplicate_kid(&self) -> bool {
        let mut seen = std::collections::HashSet::new();
        self.observed_kids
            .iter()
            .flatten()
            .any(|kid| !seen.insert(kid))
    }

    // Direct typed construction is confined to fixtures. Runtime validation still
    // refuses invalid members; this helper grants no material-admission claim.
    #[cfg(test)]
    pub(in crate::client_registry) fn from_test_keys(keys: Vec<FetchedJwk>) -> Self {
        let members: Vec<_> = keys
            .iter()
            .map(|key| serde_json::to_value(key).expect("fixture JSON"))
            .collect();
        Self {
            material_admitted: false,
            observed_kids: keys.iter().map(|key| key.kid.clone()).collect(),
            legacy_fingerprints: legacy_fingerprints(&members),
            keys,
        }
    }

    /// Test-only serialization of an owned cache body, including its original guard map.
    /// This is not a remote protocol format or production distributed body cache.
    #[cfg(test)]
    pub(in crate::client_registry) fn to_fixture_bytes(
        &self,
    ) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&(&self.keys, &self.observed_kids, &self.legacy_fingerprints))
    }

    #[cfg(test)]
    pub(in crate::client_registry) fn from_fixture_bytes(
        bytes: &[u8],
    ) -> Result<Self, serde_json::Error> {
        let (keys, observed_kids, legacy_fingerprints) = serde_json::from_slice(bytes)?;
        Ok(Self {
            material_admitted: false,
            keys,
            observed_kids,
            legacy_fingerprints,
        })
    }
}

fn legacy_fingerprints(members: &[Value]) -> HashMap<String, String> {
    members
        .iter()
        .filter_map(|member| {
            let kty = member.get("kty")?.as_str()?;
            let kid = member.get("kid")?.as_str()?;
            let components = ["n", "e", "x", "y"].map(|name| match member.get(name) {
                None | Some(Value::Null) => Some(""),
                Some(value) => value.as_str(),
            });
            let [Some(n), Some(e), Some(x), Some(y)] = components else {
                return None;
            };
            let digest =
                crate::client_registry::sha256_hex(format!("{kty}|{n}|{e}|{x}|{y}").as_bytes());
            Some((kid.to_owned(), digest))
        })
        .collect()
}

impl From<&Jwk> for FetchedJwk {
    fn from(key: &Jwk) -> Self {
        let (n, e, crv, x, y) = match &key.material {
            KeyMaterial::Rsa { n, e } => (Some(n.clone()), Some(e.clone()), None, None, None),
            KeyMaterial::Ec { crv, x, y } => (
                None,
                None,
                Some(crv.clone()),
                Some(x.clone()),
                Some(y.clone()),
            ),
        };
        Self {
            kty: key.key_type.clone(),
            kid: key.kid.clone(),
            alg: key.alg.clone(),
            key_use: key.key_use.as_ref().map(|usage| match usage {
                KeyUse::Signature => "sig".to_owned(),
                KeyUse::Encryption => "enc".to_owned(),
                KeyUse::Other(value) => value.clone(),
            }),
            key_ops: key.key_ops.clone(),
            n,
            e,
            crv,
            x,
            y,
        }
    }
}

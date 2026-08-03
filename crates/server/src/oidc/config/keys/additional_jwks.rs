use crate::jwk_types::Jwk;
#[cfg(not(kani))]
use aegaeon_pure::{Jwk as PureJwk, Jwks as PureJwks};
#[cfg(not(kani))]
use std::collections::HashMap;
use std::collections::HashSet;

use super::super::OidcConfigError;
use super::kid_is_valid;

pub(in crate::oidc::config) fn validated_additional_signing_jwks(
    additional: Vec<Jwk>,
    active_kid: Option<&str>,
) -> Result<Vec<Jwk>, OidcConfigError> {
    if additional.is_empty() {
        return Ok(additional);
    }

    let mut seen = HashSet::new();
    if let Some(active_kid) = active_kid {
        seen.insert(active_kid.to_string());
    }

    for jwk in &additional {
        validate_additional_kid(&jwk.kid)?;
        validate_additional_jwk(jwk)?;
        if !seen.insert(jwk.kid.clone()) {
            if active_kid == Some(jwk.kid.as_str()) {
                return Err(OidcConfigError::AdditionalJwksConflictingKid(
                    jwk.kid.clone(),
                ));
            }
            return Err(OidcConfigError::AdditionalJwksDuplicateKid(jwk.kid.clone()));
        }
    }

    Ok(additional)
}

#[cfg(not(kani))]
pub(in crate::oidc::config) fn merge_signing_public_jwks(
    active_public_jwk: &Jwk,
    active_kid: &str,
    additional: Vec<Jwk>,
) -> Result<Vec<Jwk>, OidcConfigError> {
    let additional = validated_additional_signing_jwks(additional, Some(active_kid))?;
    let pure_active = runtime_signing_jwk_to_pure(active_public_jwk);
    let pure_additional = runtime_signing_jwks_to_pure(&additional);
    let merged =
        aegaeon_pure::merge_active_and_additional(&pure_active, active_kid, &pure_additional)
            .ok_or_else(|| {
                OidcConfigError::AdditionalJwksInternalConsistency(
                    "validated overlap set failed pure merge invariants".to_string(),
                )
            })?;
    pure_signing_jwks_to_runtime(&merged, active_public_jwk, &additional)
}

#[cfg(kani)]
pub(in crate::oidc::config) fn merge_signing_public_jwks(
    active_public_jwk: &Jwk,
    active_kid: &str,
    additional: Vec<Jwk>,
) -> Result<Vec<Jwk>, OidcConfigError> {
    // The Kani-only `aegaeon_pure::Jwk` model is byte-sized and is not a
    // lossless projection of runtime JWKS entries. Reuse the validated runtime
    // path directly so the Kani build keeps the active-first ordering without
    // inventing a lossy string-to-byte encoding for production keys.
    let additional = validated_additional_signing_jwks(additional, Some(active_kid))?;
    let mut keys = Vec::with_capacity(1 + additional.len());
    keys.push(active_public_jwk.clone());
    keys.extend(additional);
    Ok(keys)
}

#[cfg(not(kani))]
fn runtime_signing_jwk_to_pure(jwk: &Jwk) -> PureJwk {
    PureJwk {
        kty: jwk.kty.clone(),
        kid: Some(jwk.kid.clone()),
        n: jwk.n.clone(),
        e: jwk.e.clone(),
        x: jwk.x.clone(),
        y: jwk.y.clone(),
    }
}

#[cfg(not(kani))]
fn runtime_signing_jwks_to_pure(keys: &[Jwk]) -> PureJwks {
    PureJwks {
        keys: keys.iter().map(runtime_signing_jwk_to_pure).collect(),
    }
}

#[cfg(not(kani))]
fn pure_signing_jwks_to_runtime(
    merged: &PureJwks,
    active_public_jwk: &Jwk,
    additional: &[Jwk],
) -> Result<Vec<Jwk>, OidcConfigError> {
    let active_kid = active_public_jwk.kid.as_str();
    let additional_by_kid: HashMap<&str, &Jwk> = additional
        .iter()
        .map(|jwk| (jwk.kid.as_str(), jwk))
        .collect();
    let mut keys = Vec::with_capacity(merged.keys.len());

    for pure_jwk in &merged.keys {
        let Some(kid) = pure_jwk.kid.as_deref() else {
            return Err(OidcConfigError::AdditionalJwksInternalConsistency(
                "pure overlap merge returned a key without kid".to_string(),
            ));
        };

        if kid == active_kid {
            keys.push(active_public_jwk.clone());
            continue;
        }

        let runtime_jwk = additional_by_kid.get(kid).ok_or_else(|| {
            OidcConfigError::AdditionalJwksInternalConsistency(format!(
                "pure overlap merge returned unknown kid `{kid}`"
            ))
        })?;
        keys.push((*runtime_jwk).clone());
    }

    Ok(keys)
}

fn validate_additional_kid(kid: &str) -> Result<(), OidcConfigError> {
    if kid_is_valid(kid) {
        Ok(())
    } else {
        Err(OidcConfigError::AdditionalJwksInvalidKid(kid.to_string()))
    }
}

fn validate_additional_jwk(jwk: &Jwk) -> Result<(), OidcConfigError> {
    if !jwk.kty.eq_ignore_ascii_case("RSA") {
        return Err(OidcConfigError::AdditionalJwksUnsupportedKey(format!(
            "kty must be RSA (kid={})",
            jwk.kid
        )));
    }

    if let Some(ref use_) = jwk.use_ {
        if !use_.eq_ignore_ascii_case("sig") {
            return Err(OidcConfigError::AdditionalJwksUnsupportedKey(format!(
                "use must be sig (kid={})",
                jwk.kid
            )));
        }
    }

    if let Some(ref alg) = jwk.alg {
        if !alg.eq_ignore_ascii_case("RS256") {
            return Err(OidcConfigError::AdditionalJwksUnsupportedKey(format!(
                "alg must be RS256 (kid={})",
                jwk.kid
            )));
        }
    }

    match (jwk.n.as_deref(), jwk.e.as_deref()) {
        (Some(n), Some(e)) if !n.trim().is_empty() && !e.trim().is_empty() => Ok(()),
        _ => Err(OidcConfigError::AdditionalJwksUnsupportedKey(format!(
            "RSA keys must include non-empty n and e (kid={})",
            jwk.kid
        ))),
    }
}

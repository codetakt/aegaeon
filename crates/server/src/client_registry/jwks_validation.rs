use std::collections::HashMap;
#[cfg(test)]
use std::collections::HashSet;

use super::jwks_types::{CacheEntry, FetchedJwk, FetchedJwks};
use super::{jwt_algorithm_name, metrics, sha256_hex};
use tracing::warn;

pub(super) fn validate_fetched_jwks(jwks: &FetchedJwks) -> Result<(), FetchedJwksValidationError> {
    let value =
        serde_json::to_value(jwks).map_err(|_| FetchedJwksValidationError::NotJsonObject)?;
    let set =
        aegaeon_jose::jwk::JwkSet::from_value(value).map_err(FetchedJwksValidationError::Parse)?;
    set.ensure_unique_kid()
        .map_err(FetchedJwksValidationError::DuplicateKid)?;
    if set.signature_keys().next().is_none() {
        return Err(FetchedJwksValidationError::NoSignatureKeys);
    }
    Ok(())
}

#[derive(Debug)]
pub(super) enum FetchedJwksValidationError {
    NotJsonObject,
    Parse(aegaeon_jose::jwk::JwkError),
    DuplicateKid(aegaeon_jose::jwk::JwkError),
    NoSignatureKeys,
}

impl FetchedJwksValidationError {
    fn metric_reason(&self) -> &'static str {
        match self {
            FetchedJwksValidationError::NotJsonObject => "validation_not_object",
            FetchedJwksValidationError::Parse(err) => match err {
                aegaeon_jose::jwk::JwkError::MissingField(_) => "validation_missing_field",
                aegaeon_jose::jwk::JwkError::FieldNotString { .. } => "validation_bad_field",
                aegaeon_jose::jwk::JwkError::FieldNotStringArray { .. } => "validation_bad_array",
                aegaeon_jose::jwk::JwkError::UnsupportedKeyType(_) => "validation_unsupported_kty",
                aegaeon_jose::jwk::JwkError::DuplicateKid(_) => "validation_duplicate_kid",
                aegaeon_jose::jwk::JwkError::KidRequired => "validation_kid_missing",
                aegaeon_jose::jwk::JwkError::NotAnObject => "validation_parse_error",
            },
            FetchedJwksValidationError::DuplicateKid(_) => "validation_duplicate_kid",
            FetchedJwksValidationError::NoSignatureKeys => "validation_no_sig_keys",
        }
    }
}

impl std::fmt::Display for FetchedJwksValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchedJwksValidationError::NotJsonObject => {
                write!(f, "JWKS payload is not a JSON object")
            }
            FetchedJwksValidationError::Parse(err) => write!(f, "invalid JWK: {err}"),
            FetchedJwksValidationError::DuplicateKid(err) => write!(f, "duplicate kid: {err}"),
            FetchedJwksValidationError::NoSignatureKeys => {
                write!(f, "JWKS does not contain any signature-capable keys")
            }
        }
    }
}

pub(super) fn record_validation_failure(
    uri: &str,
    err: &FetchedJwksValidationError,
    context: &str,
    uri_hash: Option<&str>,
) {
    if matches!(
        err,
        FetchedJwksValidationError::DuplicateKid(_)
            | FetchedJwksValidationError::Parse(aegaeon_jose::jwk::JwkError::DuplicateKid(_))
    ) {
        metrics::record_jwks_kid_duplicate();
    }
    let reason = err.metric_reason();
    if let Some(hash) = uri_hash {
        metrics::record_jwks_http_failure_reason(reason, hash);
    }
    warn!(
        target: "jwks",
        uri = %uri,
        reason = %reason,
        context = %context,
        "JWKS validation failed: {err}"
    );
}

pub(super) fn build_kid_fingerprints(jwks: &FetchedJwks) -> HashMap<String, String> {
    jwks.keys
        .iter()
        .filter_map(|key| {
            let kid = key.kid.as_ref()?;
            let material = format!(
                "{}|{}|{}|{}|{}",
                key.kty,
                key.n.as_deref().unwrap_or(""),
                key.e.as_deref().unwrap_or(""),
                key.x.as_deref().unwrap_or(""),
                key.y.as_deref().unwrap_or("")
            );
            Some((kid.clone(), sha256_hex(material.as_bytes())))
        })
        .collect()
}

#[cfg(test)]
pub(super) fn has_duplicate_kid(jwks: &FetchedJwks) -> bool {
    jwks.keys
        .iter()
        .filter_map(|key| key.kid.as_deref())
        .try_fold(HashSet::new(), |mut seen, kid| {
            seen.insert(kid).then_some(seen)
        })
        .is_none()
}

pub(super) fn kid_reuse_changed(prev: &CacheEntry, new_map: &HashMap<String, String>) -> bool {
    new_map.iter().any(|(kid, new_fp)| {
        prev.kid_fps
            .get(kid)
            .is_some_and(|prev_fp| prev_fp != new_fp)
    })
}

pub(super) fn select_jwk(jwks: &FetchedJwks, kid: Option<&str>) -> Option<FetchedJwk> {
    if let Some(kid) = kid {
        return jwks
            .keys
            .iter()
            .find(|jwk| jwk.kid.as_deref() == Some(kid) && fetched_jwk_signature_capable(jwk))
            .cloned();
    }

    let mut keys = jwks
        .keys
        .iter()
        .filter(|jwk| fetched_jwk_signature_capable(jwk));
    let key = keys.next()?;
    keys.next().is_none().then_some(key.clone())
}

fn fetched_jwk_signature_capable(jwk: &FetchedJwk) -> bool {
    if jwk
        .key_use
        .as_deref()
        .is_some_and(|key_use| key_use.eq_ignore_ascii_case("enc"))
    {
        return false;
    }

    jwk.key_ops.as_ref().is_none_or(|ops| {
        ops.iter()
            .any(|op| op.eq_ignore_ascii_case("sign") || op.eq_ignore_ascii_case("verify"))
    })
}

pub(super) fn jwk_alg_allows(
    registered_alg: Option<&str>,
    token_alg: jsonwebtoken::Algorithm,
) -> bool {
    let Some(registered_alg) = registered_alg else {
        return true;
    };
    jwt_algorithm_name(token_alg).is_some_and(|token_alg| registered_alg == token_alg)
}

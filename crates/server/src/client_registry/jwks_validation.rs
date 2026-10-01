use std::collections::HashMap;

#[cfg(any(test, kani))]
use super::jwks_types::CacheEntry;
use super::jwks_types::{FetchedJwk, FetchedJwks};
use super::{jwt_algorithm_name, metrics};
use tracing::warn;

pub(super) fn validate_fetched_jwks(jwks: &FetchedJwks) -> Result<(), FetchedJwksValidationError> {
    let value =
        serde_json::to_value(jwks).map_err(|_| FetchedJwksValidationError::NotJsonObject)?;
    let set = aegaeon_jose::jwk::JwkSet::from_verification_value(value)
        .map_err(FetchedJwksValidationError::Parse)?;
    if jwks.has_duplicate_kid() {
        return Err(FetchedJwksValidationError::DuplicateKid(
            aegaeon_jose::jwk::JwkError::DuplicateKid("duplicate".into()),
        ));
    }
    set.ensure_unique_kid()
        .map_err(FetchedJwksValidationError::DuplicateKid)?;
    if set.keys().is_empty() || set.keys().len() != jwks.keys.len() {
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
                aegaeon_jose::jwk::JwkError::DuplicateKeyOperation(_) => {
                    "validation_duplicate_key_op"
                }
                aegaeon_jose::jwk::JwkError::InconsistentKeyUsage => {
                    "validation_inconsistent_key_usage"
                }
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
    jwks.legacy_fingerprints().clone()
}

#[cfg(test)]
pub(super) fn has_duplicate_kid(jwks: &FetchedJwks) -> bool {
    jwks.has_duplicate_kid()
}

#[cfg(any(test, kani))]
pub(super) fn kid_reuse_changed(prev: &CacheEntry, new_map: &HashMap<String, String>) -> bool {
    prev.guard.conflicts(new_map)
}

pub(super) fn select_jwk(jwks: &FetchedJwks, kid: Option<&str>) -> Option<FetchedJwk> {
    validate_fetched_jwks(jwks).ok()?;
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
    aegaeon_jose::jwk::verification_usage_allowed(jwk.key_use.as_deref(), jwk.key_ops.as_deref())
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

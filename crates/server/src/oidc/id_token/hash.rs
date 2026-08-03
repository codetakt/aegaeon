use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ffi::id_token::{self as ffi_id_token, OidcHashError};
use tracing::debug;

use super::{Error, Result};

/// Compute hash for `at_hash/c_hash` per OIDC spec.
pub(super) fn compute_hash(input: &str, alg: &str) -> Result<String> {
    if matches!(alg, "PS256" | "PS384" | "PS512") {
        return Err(Error::InvalidRequest(format!(
            "Algorithm {alg} is temporarily disabled due to security vulnerability"
        )));
    }

    finalize_hash_result(
        ffi_id_token::compute_oidc_hash_bytes(alg, input.as_bytes()),
        input,
        alg,
    )
}

pub(super) fn finalize_hash_result(
    lowstar_result: std::result::Result<Vec<u8>, OidcHashError>,
    input: &str,
    alg: &str,
) -> Result<String> {
    match lowstar_result {
        Ok(bytes) => return Ok(URL_SAFE_NO_PAD.encode(bytes)),
        Err(OidcHashError::InputTooLarge) => {
            return Err(Error::InvalidRequest(
                "OIDC hash input exceeds 4 GiB".into(),
            ));
        }
        Err(OidcHashError::InvalidAlgorithm) => {
            return Err(Error::InvalidRequest(format!(
                "Unsupported algorithm: {alg}"
            )));
        }
        Err(OidcHashError::Unavailable) if cfg!(feature = "verified-claim") => {
            return Err(Error::ServerError(
                "OIDC hash verified path unavailable".into(),
            ));
        }
        Err(OidcHashError::Unavailable) => {}
        Err(other) if cfg!(feature = "verified-claim") => {
            debug!(
                ?other,
                "OIDC hash verified path failed closed in verified-claim profile"
            );
            return Err(Error::ServerError("OIDC hash verified path failed".into()));
        }
        Err(other) => {
            debug!(
                ?other,
                "Low* hash computation failed; falling back to Rust implementation"
            );
        }
    }

    let hash_bytes = match alg {
        // PS* algorithms temporarily disabled due to RSA vulnerability.
        "PS256" | "PS384" | "PS512" => {
            return Err(Error::InvalidRequest(format!(
                "Algorithm {alg} is temporarily disabled due to security vulnerability"
            )))
        }
        "RS256" | "ES256" | "HS256" => {
            let hash = aegaeon_crypto::hash::sha256_digest(input.as_bytes());
            URL_SAFE_NO_PAD.encode(&hash[..16])
        }
        "RS384" | "ES384" | "HS384" => {
            let hash = aegaeon_crypto::hash::sha384_digest(input.as_bytes());
            URL_SAFE_NO_PAD.encode(&hash[..24])
        }
        "RS512" | "ES512" | "HS512" => {
            let hash = aegaeon_crypto::hash::sha512_digest(input.as_bytes());
            URL_SAFE_NO_PAD.encode(&hash[..32])
        }
        _ => {
            return Err(Error::InvalidRequest(format!(
                "Unsupported algorithm: {alg}"
            )))
        }
    };

    Ok(hash_bytes)
}

pub(super) fn verify_optional_hash(
    source: Option<&str>,
    provided: Option<&str>,
    alg: &str,
    label: &str,
) -> Result<()> {
    match (source, provided) {
        (Some(value), Some(hash)) => {
            let computed = compute_hash(value, alg)?;
            if computed == hash {
                Ok(())
            } else {
                Err(Error::InvalidRequest(format!("{label} mismatch")))
            }
        }
        (Some(_), None) => Err(Error::InvalidRequest(format!("{label} missing"))),
        (None, _) => Ok(()),
    }
}

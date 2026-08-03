use aegaeon_jose::jwk::{Jwk, KeyMaterial};
use aegaeon_jose::jws::VerificationKey;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use super::FederationError;

/// Decoded key material from a JWK, owning the raw bytes.
#[derive(Debug)]
pub struct DecodedKeyMaterial {
    /// Primary key data.
    pub data: Vec<u8>,
    /// Secondary key data, such as an RSA exponent.
    pub extra: Vec<u8>,
}

/// Decode a JWK's key material into raw bytes.
///
/// # Errors
///
/// Returns [`FederationError`] when the JWK uses unsupported parameters or invalid key material.
pub fn decode_jwk_material(jwk: &Jwk) -> Result<DecodedKeyMaterial, FederationError> {
    match &jwk.material {
        KeyMaterial::Rsa { n, e } => {
            let modulus = URL_SAFE_NO_PAD.decode(n)?;
            let exponent = URL_SAFE_NO_PAD.decode(e)?;
            Ok(DecodedKeyMaterial {
                data: modulus,
                extra: exponent,
            })
        }
        KeyMaterial::Ec { crv, x, y } => {
            if crv != "P-256" {
                return Err(FederationError::UnsupportedAlgorithm(format!(
                    "EC curve {crv}"
                )));
            }
            let x_bytes = URL_SAFE_NO_PAD.decode(x)?;
            let y_bytes = URL_SAFE_NO_PAD.decode(y)?;
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            pad_left(&mut sec1, &x_bytes, 32);
            pad_left(&mut sec1, &y_bytes, 32);
            Ok(DecodedKeyMaterial {
                data: sec1,
                extra: Vec::new(),
            })
        }
    }
}

fn pad_left(out: &mut Vec<u8>, bytes: &[u8], target_len: usize) {
    if bytes.len() < target_len {
        out.extend(std::iter::repeat_n(0u8, target_len - bytes.len()));
    }
    out.extend_from_slice(bytes);
}

/// Build a [`VerificationKey`] from a JWK and its decoded material.
///
/// # Errors
///
/// Returns [`FederationError`] when the JWK does not match the requested algorithm.
pub fn verification_key_for_alg<'a>(
    jwk: &Jwk,
    decoded: &'a DecodedKeyMaterial,
    jws_alg: &str,
) -> Result<VerificationKey<'a>, FederationError> {
    if let Some(ref jwk_alg) = jwk.alg {
        if jwk_alg != jws_alg {
            return Err(FederationError::NoSuitableKey);
        }
    }

    match jws_alg {
        "RS256" => rsa_key(jwk, decoded, |modulus, exponent| {
            VerificationKey::RsaPkcs1Sha256 { modulus, exponent }
        }),
        "PS256" => rsa_key(jwk, decoded, |modulus, exponent| {
            VerificationKey::RsaPssSha256 { modulus, exponent }
        }),
        "ES256" => ec_p256_key(jwk, decoded),
        other => Err(FederationError::UnsupportedAlgorithm(other.to_string())),
    }
}

fn rsa_key<'a, F>(
    jwk: &Jwk,
    decoded: &'a DecodedKeyMaterial,
    build: F,
) -> Result<VerificationKey<'a>, FederationError>
where
    F: FnOnce(&'a [u8], &'a [u8]) -> VerificationKey<'a>,
{
    if !matches!(jwk.material, KeyMaterial::Rsa { .. }) {
        return Err(FederationError::NoSuitableKey);
    }
    Ok(build(&decoded.data, &decoded.extra))
}

fn ec_p256_key<'a>(
    jwk: &Jwk,
    decoded: &'a DecodedKeyMaterial,
) -> Result<VerificationKey<'a>, FederationError> {
    if !matches!(jwk.material, KeyMaterial::Ec { ref crv, .. } if crv == "P-256") {
        return Err(FederationError::NoSuitableKey);
    }
    Ok(VerificationKey::EcdsaP256Sha256(&decoded.data))
}

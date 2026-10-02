//! Standalone admission of supported public signature-key material.

use aws_lc_rs::{rsa::PublicKey, signature};

use crate::CryptoError;

fn invalid() -> CryptoError {
    CryptoError::InvalidKey("unsupported public signature key material".into())
}

/// Validate minimal unsigned RSA components without performing a signature operation.
///
/// Requires an odd 2048..=16384-bit modulus and an odd exponent in 3..=2^33-1.
/// The lower bound is the RS/PS protocol minimum; the upper bounds are this
/// provider's supported parsing limits. Actual signature algorithms can impose
/// tighter limits. This does not prove factorization, primality or key possession.
///
/// # Errors
/// Returns a fixed `InvalidKey` error for unsupported encoding or material.
pub fn validate_rsa_verification_components(n: &[u8], e: &[u8]) -> Result<(), CryptoError> {
    if n.is_empty() || n.len() > 2048 || e.is_empty() || e.len() > 5 {
        return Err(invalid());
    }
    if n[0] == 0 || e[0] == 0 || n[n.len() - 1] & 1 == 0 || e[e.len() - 1] & 1 == 0 {
        return Err(invalid());
    }
    let bits = n.len() * 8 - n[0].leading_zeros() as usize;
    let exponent = e
        .iter()
        .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
    if !(2048..=16384).contains(&bits) || !(3..=(1_u64 << 33) - 1).contains(&exponent) {
        return Err(invalid());
    }
    let mut components = Vec::with_capacity(n.len() + e.len() + 12);
    integer(&mut components, n)?;
    integer(&mut components, e)?;
    let mut der = Vec::with_capacity(components.len() + 4);
    der.push(0x30);
    length(&mut der, components.len())?;
    der.extend_from_slice(&components);
    PublicKey::from_der(&der).map(|_| ()).map_err(|_| invalid())
}

fn length(out: &mut Vec<u8>, len: usize) -> Result<(), CryptoError> {
    let len = u16::try_from(len).map_err(|_| invalid())?;
    match len {
        0..=127 => out.push(u8::try_from(len).map_err(|_| invalid())?),
        128..=255 => out.extend_from_slice(&[0x81, u8::try_from(len).map_err(|_| invalid())?]),
        _ => {
            out.push(0x82);
            out.extend_from_slice(&len.to_be_bytes());
        }
    }
    Ok(())
}

fn integer(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CryptoError> {
    let sign_pad = usize::from(bytes[0] & 0x80 != 0);
    out.push(0x02);
    length(out, bytes.len().checked_add(sign_pad).ok_or_else(invalid)?)?;
    if sign_pad != 0 {
        out.push(0);
    }
    out.extend_from_slice(bytes);
    Ok(())
}

/// Validate a finite point on the exact supported curve in uncompressed SEC1 form.
///
/// # Errors
/// Returns a fixed `InvalidKey` error for an unsupported curve, format or point.
pub fn validate_ec_verification_point(curve: &str, point: &[u8]) -> Result<(), CryptoError> {
    let (size, algorithm): (usize, &'static dyn signature::VerificationAlgorithm) = match curve {
        "P-256" => (65, &signature::ECDSA_P256_SHA256_FIXED),
        "P-384" => (97, &signature::ECDSA_P384_SHA384_FIXED),
        _ => return Err(invalid()),
    };
    if point.len() != size || point.first() != Some(&4) {
        return Err(invalid());
    }
    signature::ParsedPublicKey::new(algorithm, point)
        .map(|_| ())
        .map_err(|_| invalid())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::KeyPair as _;

    #[test]
    fn public_rsa_admission_accepts_generated_key_and_refuses_integer_boundaries() {
        let pair = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        let key = aws_lc_rs::rsa::PublicKeyComponents::from(pair.public_key());
        assert!(validate_rsa_verification_components(&key.n, &key.e).is_ok());
        let mut even = key.n.clone();
        *even.last_mut().unwrap() &= 0xfe;
        let mut prefixed = vec![0];
        prefixed.extend_from_slice(&key.n);
        for n in [
            vec![],
            vec![0],
            vec![1],
            vec![0xff; 255],
            prefixed,
            even,
            vec![0xff; 2049],
        ] {
            assert!(validate_rsa_verification_components(&n, &key.e).is_err());
        }
        for e in [
            vec![],
            vec![0],
            vec![1],
            vec![2],
            vec![4],
            vec![0, 3],
            vec![2, 0, 0, 0, 1],
        ] {
            assert!(validate_rsa_verification_components(&key.n, &e).is_err());
        }
        // Public-shape limits only: these artificial odd moduli are not claimed
        // to be generated RSA keys or to support genuine signatures.
        for bytes in [256, 2048] {
            let n = vec![0xff; bytes];
            for e in [vec![3], vec![1, 0xff, 0xff, 0xff, 0xff]] {
                assert!(validate_rsa_verification_components(&n, &e).is_ok());
            }
        }
        let mut below = vec![0xff; 256];
        below[0] = 0x7f;
        assert!(validate_rsa_verification_components(&below, &key.e).is_err());
    }

    #[test]
    fn public_ec_admission_checks_actual_curve_points_and_uncompressed_format() {
        for (curve, algorithm) in [
            ("P-256", &signature::ECDSA_P256_SHA256_FIXED_SIGNING),
            ("P-384", &signature::ECDSA_P384_SHA384_FIXED_SIGNING),
        ] {
            let pair = signature::EcdsaKeyPair::generate(algorithm).unwrap();
            let point = pair.public_key().as_ref();
            assert!(validate_ec_verification_point(curve, point).is_ok());
            let mut off_curve = vec![0; point.len()];
            off_curve[0] = 4;
            let mut hybrid = point.to_vec();
            hybrid[0] = 6;
            for bad in [vec![0], off_curve, hybrid, point[1..].to_vec()] {
                assert!(validate_ec_verification_point(curve, &bad).is_err());
            }
            assert!(validate_ec_verification_point("p-256", point).is_err());
            let other = if curve == "P-256" { "P-384" } else { "P-256" };
            assert!(validate_ec_verification_point(other, point).is_err());
        }
    }

    #[test]
    fn public_rsa_der_encoder_handles_sign_padding_and_length_transitions() {
        for (size, expected) in [
            (127, vec![127]),
            (128, vec![0x81, 128]),
            (255, vec![0x81, 255]),
            (256, vec![0x82, 1, 0]),
        ] {
            let mut encoded = Vec::new();
            length(&mut encoded, size).unwrap();
            assert_eq!(encoded, expected);
        }
        assert!(length(&mut Vec::new(), 65536).is_err());
        let mut encoded = Vec::new();
        integer(&mut encoded, &[0x80]).unwrap();
        assert_eq!(encoded, [2, 2, 0, 0x80]);
        encoded.clear();
        integer(&mut encoded, &[0x7f]).unwrap();
        assert_eq!(encoded, [2, 1, 0x7f]);
    }
}

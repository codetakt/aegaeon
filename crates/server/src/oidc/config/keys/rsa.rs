use crate::jwk_types::Jwk;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use simple_asn1::ASN1Block;

use super::super::OidcConfigError;

#[cfg(test)]
pub(super) fn rsa_public_jwk_from_private_pem(
    kid: &str,
    private_pem: &str,
) -> Result<Jwk, OidcConfigError> {
    let parsed = pem::parse(private_pem)?;
    rsa_public_jwk_from_private_der(kid, parsed.contents())
}

pub(in crate::oidc::config) fn rsa_public_jwk_from_private_der(
    kid: &str,
    private_der: &[u8],
) -> Result<Jwk, OidcConfigError> {
    let (n, e) = rsa_public_components_from_private_der(private_der)?;
    Ok(rsa_public_jwk(kid, "sig", "RS256", n, e))
}

pub(super) fn rsa_request_object_encryption_public_jwk_from_pkcs8_der(
    kid: &str,
    private_der: &[u8],
) -> Result<Jwk, OidcConfigError> {
    let (n, e) =
        rsa_public_components_from_pkcs8_private_der_for_request_object_encryption(private_der)?;
    Ok(rsa_public_jwk(kid, "enc", "RSA-OAEP", n, e))
}

fn rsa_public_jwk(kid: &str, use_: &str, alg: &str, n: Vec<u8>, e: Vec<u8>) -> Jwk {
    Jwk {
        kty: "RSA".to_string(),
        use_: Some(use_.to_string()),
        kid: kid.to_string(),
        alg: Some(alg.to_string()),
        n: Some(URL_SAFE_NO_PAD.encode(n)),
        e: Some(URL_SAFE_NO_PAD.encode(e)),
        x: None,
        y: None,
        crv: None,
    }
}

fn rsa_public_components_from_private_der(
    der: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), OidcConfigError> {
    let blocks = simple_asn1::from_der(der)?;
    let Some(ASN1Block::Sequence(_, seq)) = blocks.first() else {
        return Err(OidcConfigError::SigningKeyUnsupportedFormat);
    };

    // PKCS#8: PrivateKeyInfo ::= SEQUENCE { version, algorithm, privateKey OCTET STRING, ... }
    if seq.len() >= 3 {
        if let ASN1Block::OctetString(_, private_key) = &seq[2] {
            return rsa_public_components_from_private_der(private_key);
        }
    }

    // PKCS#1: RSAPrivateKey ::= SEQUENCE { version, modulus INTEGER, publicExponent INTEGER, ... }
    if seq.len() >= 3 {
        let modulus = match &seq[1] {
            ASN1Block::Integer(_, n) => n
                .to_biguint()
                .ok_or(OidcConfigError::SigningKeyUnsupportedFormat)?,
            _ => return Err(OidcConfigError::SigningKeyUnsupportedFormat),
        };
        let exponent = match &seq[2] {
            ASN1Block::Integer(_, e) => e
                .to_biguint()
                .ok_or(OidcConfigError::SigningKeyUnsupportedFormat)?,
            _ => return Err(OidcConfigError::SigningKeyUnsupportedFormat),
        };
        return Ok((modulus.to_bytes_be(), exponent.to_bytes_be()));
    }

    Err(OidcConfigError::SigningKeyUnsupportedFormat)
}

fn rsa_public_components_from_pkcs8_private_der_for_request_object_encryption(
    der: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), OidcConfigError> {
    let blocks =
        simple_asn1::from_der(der).map_err(OidcConfigError::RequestObjectEncryptionKeyAsn1)?;
    let Some(ASN1Block::Sequence(_, seq)) = blocks.first() else {
        return Err(OidcConfigError::RequestObjectEncryptionKeyUnsupportedFormat);
    };

    // PKCS#8: PrivateKeyInfo ::= SEQUENCE { version, algorithm, privateKey OCTET STRING, ... }
    if seq.len() >= 3 {
        if let ASN1Block::OctetString(_, private_key) = &seq[2] {
            let inner = simple_asn1::from_der(private_key)
                .map_err(OidcConfigError::RequestObjectEncryptionKeyAsn1)?;
            let Some(ASN1Block::Sequence(_, inner_seq)) = inner.first() else {
                return Err(OidcConfigError::RequestObjectEncryptionKeyUnsupportedFormat);
            };

            // PKCS#1: RSAPrivateKey ::= SEQUENCE {
            //   version, modulus INTEGER, publicExponent INTEGER, ...
            // }
            if inner_seq.len() >= 3 {
                let modulus = match &inner_seq[1] {
                    ASN1Block::Integer(_, n) => n
                        .to_biguint()
                        .ok_or(OidcConfigError::RequestObjectEncryptionKeyUnsupportedFormat)?,
                    _ => return Err(OidcConfigError::RequestObjectEncryptionKeyUnsupportedFormat),
                };
                let exponent = match &inner_seq[2] {
                    ASN1Block::Integer(_, e) => e
                        .to_biguint()
                        .ok_or(OidcConfigError::RequestObjectEncryptionKeyUnsupportedFormat)?,
                    _ => return Err(OidcConfigError::RequestObjectEncryptionKeyUnsupportedFormat),
                };
                return Ok((modulus.to_bytes_be(), exponent.to_bytes_be()));
            }

            return Err(OidcConfigError::RequestObjectEncryptionKeyUnsupportedFormat);
        }
    }

    // PKCS#1: reject (Request Object decryptor expects PKCS#8 at the top level).
    Err(OidcConfigError::RequestObjectEncryptionKeyUnsupportedFormat)
}

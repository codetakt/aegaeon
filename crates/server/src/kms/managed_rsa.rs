//! Local purpose-specific RSA signing material. It owns only explicitly imported keys.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ring::signature::KeyPair as _;
use simple_asn1::ASN1Block;

use super::KeyManagerError;
use crate::jwk_types::Jwk;

pub(crate) struct ManagedRsaSigningKey(ring::signature::RsaKeyPair);

impl ManagedRsaSigningKey {
    /// Initialize the actual signing primitive, enforcing its 2048..4096-bit range.
    pub(crate) fn from_pkcs8(der: &[u8]) -> Result<Self, KeyManagerError> {
        ring::signature::RsaKeyPair::from_pkcs8(der)
            .map(Self)
            .map_err(|_| KeyManagerError::OperationFailed)
    }

    pub(crate) fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        let mut signature = vec![0; self.0.public().modulus_len()];
        self.0
            .sign(
                &ring::signature::RSA_PKCS1_SHA256,
                &ring::rand::SystemRandom::new(),
                msg,
                &mut signature,
            )
            .map_err(|_| KeyManagerError::OperationFailed)?;
        Ok(signature)
    }

    pub(crate) fn public_jwk(&self, kid: &str) -> Result<Jwk, KeyManagerError> {
        // Parse only the public PKCS#1 representation emitted by the validated primitive.
        let blocks = simple_asn1::from_der(self.0.public_key().as_ref())
            .map_err(|_| KeyManagerError::OperationFailed)?;
        let [ASN1Block::Sequence(_, fields)] = blocks.as_slice() else {
            return Err(KeyManagerError::OperationFailed);
        };
        let [ASN1Block::Integer(_, n), ASN1Block::Integer(_, e)] = fields.as_slice() else {
            return Err(KeyManagerError::OperationFailed);
        };
        let n = n.to_biguint().ok_or(KeyManagerError::OperationFailed)?;
        let e = e.to_biguint().ok_or(KeyManagerError::OperationFailed)?;
        Ok(Jwk {
            kty: "RSA".into(),
            use_: Some("sig".into()),
            kid: kid.into(),
            alg: Some("RS256".into()),
            n: Some(URL_SAFE_NO_PAD.encode(n.to_bytes_be())),
            e: Some(URL_SAFE_NO_PAD.encode(e.to_bytes_be())),
            x: None,
            y: None,
            crv: None,
        })
    }
}

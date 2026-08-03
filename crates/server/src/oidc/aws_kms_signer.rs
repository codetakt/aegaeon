use crate::jwk_types::Jwk;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_kms::config::Region;
use aws_sdk_kms::{
    primitives::Blob,
    types::{KeySpec, MessageType, SigningAlgorithmSpec},
    Client,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Serialize;
use simple_asn1::ASN1Block;
use std::future::Future;
use tokio::runtime::{Handle, RuntimeFlavor};

#[derive(Debug, thiserror::Error)]
pub(crate) enum OidcAwsKmsSignerError {
    #[error("OIDC KMS kid must be non-empty ASCII without whitespace and <= 128 bytes: `{0}`")]
    InvalidKid(String),
    #[error("failed to create tokio runtime for OIDC KMS signer: {0}")]
    Runtime(std::io::Error),
    #[error("OIDC AWS KMS signer cannot synchronously wait on this Tokio runtime: {0}")]
    RuntimeContext(&'static str),
    #[error("AWS KMS public-key fetch failed: {0}")]
    GetPublicKey(String),
    #[error("AWS KMS key spec is not RSA signing compatible")]
    UnsupportedKeySpec,
    #[error("AWS KMS key does not advertise RS256 signing")]
    UnsupportedAlgorithm,
    #[error("AWS KMS public key is not a parseable RSA SubjectPublicKeyInfo")]
    InvalidPublicKey,
    #[error("failed to serialize JWT header or claims: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("AWS KMS sign failed: {0}")]
    Sign(String),
}

pub(crate) struct OidcAwsKmsSigner {
    client: Client,
    key_id: String,
    kid: String,
    public_jwk: Jwk,
}

impl std::fmt::Debug for OidcAwsKmsSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcAwsKmsSigner")
            .field("key_id", &self.key_id)
            .field("kid", &self.kid)
            .field("public_jwk", &self.public_jwk)
            .finish_non_exhaustive()
    }
}

impl OidcAwsKmsSigner {
    /// # Errors
    ///
    /// Returns an error when the AWS client/runtime cannot be initialized, the
    /// key does not expose an RSA public key usable for RS256, or the `kid` is
    /// invalid.
    pub(crate) fn new(
        region: String,
        key_id: String,
        kid: String,
    ) -> Result<Self, OidcAwsKmsSignerError> {
        block_on_aws_kms(Self::new_async(region, key_id, kid))?
    }

    /// # Errors
    ///
    /// Returns an error when the AWS client cannot be initialized, the key does
    /// not expose an RSA public key usable for RS256, or the `kid` is invalid.
    pub(crate) async fn new_async(
        region: String,
        key_id: String,
        kid: String,
    ) -> Result<Self, OidcAwsKmsSignerError> {
        validate_kid(&kid)?;

        let region_provider = RegionProviderChain::first_try(Region::new(region));
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(region_provider)
            .load()
            .await;
        let client = Client::new(&config);
        let public_jwk = fetch_public_jwk_async(&client, &key_id, &kid).await?;

        Ok(Self {
            client,
            key_id,
            kid,
            public_jwk,
        })
    }

    #[must_use]
    pub(crate) fn public_jwk(&self) -> &Jwk {
        &self.public_jwk
    }

    /// # Errors
    ///
    /// Returns an error when the JWT cannot be serialized or the KMS sign
    /// request fails.
    pub(crate) fn sign_rs256_jwt<T: Serialize>(
        &self,
        claims: &T,
    ) -> Result<String, OidcAwsKmsSignerError> {
        block_on_aws_kms(self.sign_rs256_jwt_async(claims))?
    }

    /// # Errors
    ///
    /// Returns an error when the JWT cannot be serialized or the KMS sign
    /// request fails.
    pub(crate) async fn sign_rs256_jwt_async<T: Serialize>(
        &self,
        claims: &T,
    ) -> Result<String, OidcAwsKmsSignerError> {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.typ = Some("JWT".to_string());
        header.kid = Some(self.kid.clone());

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
        let signing_input = format!("{header_b64}.{payload_b64}");

        let signature = self
            .client
            .sign()
            .key_id(self.key_id.clone())
            .message(Blob::new(signing_input.as_bytes().to_vec()))
            .message_type(MessageType::Raw)
            .signing_algorithm(SigningAlgorithmSpec::RsassaPkcs1V15Sha256)
            .send()
            .await
            .map_err(|err| OidcAwsKmsSignerError::Sign(err.to_string()))?
            .signature()
            .cloned()
            .ok_or_else(|| OidcAwsKmsSignerError::Sign("missing signature".to_string()))?;

        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.into_inner())
        ))
    }
}

fn block_on_aws_kms<T>(future: impl Future<Output = T>) -> Result<T, OidcAwsKmsSignerError> {
    match Handle::try_current() {
        Ok(handle) => match handle.runtime_flavor() {
            RuntimeFlavor::MultiThread => {
                Ok(tokio::task::block_in_place(|| handle.block_on(future)))
            }
            RuntimeFlavor::CurrentThread => Err(OidcAwsKmsSignerError::RuntimeContext(
                "current-thread runtime cannot block for AWS KMS operations",
            )),
            _ => Err(OidcAwsKmsSignerError::RuntimeContext(
                "unknown runtime flavor cannot block for AWS KMS operations",
            )),
        },
        Err(_) => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(OidcAwsKmsSignerError::Runtime)?;
            Ok(runtime.block_on(future))
        }
    }
}

async fn fetch_public_jwk_async(
    client: &Client,
    key_id: &str,
    kid: &str,
) -> Result<Jwk, OidcAwsKmsSignerError> {
    let output = client
        .get_public_key()
        .key_id(key_id)
        .send()
        .await
        .map_err(|err| OidcAwsKmsSignerError::GetPublicKey(err.to_string()))?;

    let key_spec = output.key_spec();
    if !matches!(
        key_spec,
        Some(KeySpec::Rsa2048 | KeySpec::Rsa3072 | KeySpec::Rsa4096)
    ) {
        return Err(OidcAwsKmsSignerError::UnsupportedKeySpec);
    }

    let supports_rs256 = output
        .signing_algorithms()
        .contains(&SigningAlgorithmSpec::RsassaPkcs1V15Sha256);
    if !supports_rs256 {
        return Err(OidcAwsKmsSignerError::UnsupportedAlgorithm);
    }

    let public_key_der = output
        .public_key()
        .map(std::convert::AsRef::as_ref)
        .ok_or(OidcAwsKmsSignerError::InvalidPublicKey)?;

    rsa_signing_jwk_from_spki_public_der(kid, public_key_der)
}

fn rsa_signing_jwk_from_spki_public_der(
    kid: &str,
    der: &[u8],
) -> Result<Jwk, OidcAwsKmsSignerError> {
    let (modulus, exponent) = rsa_public_components_from_spki_public_der(der)
        .ok_or(OidcAwsKmsSignerError::InvalidPublicKey)?;

    Ok(Jwk {
        kty: "RSA".to_string(),
        use_: Some("sig".to_string()),
        kid: kid.to_string(),
        alg: Some("RS256".to_string()),
        n: Some(URL_SAFE_NO_PAD.encode(modulus)),
        e: Some(URL_SAFE_NO_PAD.encode(exponent)),
        x: None,
        y: None,
        crv: None,
    })
}

fn rsa_public_components_from_public_der(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let blocks = simple_asn1::from_der(der).ok()?;
    let ASN1Block::Sequence(_, seq) = blocks.first()? else {
        return None;
    };
    if seq.len() < 2 {
        return None;
    }
    let modulus = match &seq[0] {
        ASN1Block::Integer(_, n) => n.to_biguint()?.to_bytes_be(),
        _ => return None,
    };
    let exponent = match &seq[1] {
        ASN1Block::Integer(_, e) => e.to_biguint()?.to_bytes_be(),
        _ => return None,
    };
    Some((modulus, exponent))
}

fn rsa_public_components_from_spki_public_der(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let blocks = simple_asn1::from_der(der).ok()?;
    let ASN1Block::Sequence(_, seq) = blocks.first()? else {
        return None;
    };
    if seq.len() < 2 {
        return None;
    }
    let ASN1Block::BitString(_, _bit_len, public_key) = &seq[1] else {
        return None;
    };
    rsa_public_components_from_public_der(public_key).or_else(|| {
        public_key
            .strip_prefix(&[0x00])
            .and_then(rsa_public_components_from_public_der)
    })
}

fn validate_kid(kid: &str) -> Result<(), OidcAwsKmsSignerError> {
    let valid = !kid.is_empty()
        && kid.len() <= 128
        && kid.is_ascii()
        && !kid.chars().any(char::is_whitespace);
    if valid {
        Ok(())
    } else {
        Err(OidcAwsKmsSignerError::InvalidKid(kid.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as StdError;
    use std::io;

    type TestResult = std::result::Result<(), Box<dyn StdError>>;

    fn require_err<T, E>(
        result: std::result::Result<T, E>,
        message: &str,
    ) -> std::result::Result<E, io::Error> {
        match result {
            Ok(_) => Err(io::Error::other(message)),
            Err(err) => Ok(err),
        }
    }

    const TEST_RSA_PUBLIC_KEY_PEM: &str = include_str!("../../tests/fixtures/rsa2048-public.pem");

    #[test]
    fn oidc_kms_signer_builds_jwk_from_spki_public_key() -> TestResult {
        let parsed = pem::parse(TEST_RSA_PUBLIC_KEY_PEM)?;
        let jwk = rsa_signing_jwk_from_spki_public_der("kms-test-kid", parsed.contents())?;

        assert_eq!(jwk.kty, "RSA");
        assert_eq!(jwk.use_.as_deref(), Some("sig"));
        assert_eq!(jwk.kid, "kms-test-kid");
        assert_eq!(jwk.alg.as_deref(), Some("RS256"));
        assert!(jwk.n.as_deref().is_some_and(|value| !value.is_empty()));
        assert!(jwk.e.as_deref().is_some_and(|value| !value.is_empty()));
        Ok(())
    }

    #[test]
    fn oidc_kms_signer_rejects_invalid_kid() -> TestResult {
        let err = require_err(validate_kid("bad kid"), "kid must fail")?;
        assert!(matches!(err, OidcAwsKmsSignerError::InvalidKid(_)));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn oidc_kms_blocking_rejects_current_thread_runtime_without_panic() -> TestResult {
        let err = require_err(
            block_on_aws_kms(async { 1u8 }),
            "current-thread runtime must not be used for sync KMS wait",
        )?;
        assert!(matches!(err, OidcAwsKmsSignerError::RuntimeContext(_)));
        Ok(())
    }
}

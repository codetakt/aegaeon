use crate::jwk_types::{Jwk, Jwks};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "kms-aws")]
use crate::oidc::aws_kms_signer::OidcAwsKmsSigner;

use super::{OidcConfigError, OidcSigningError};

mod additional_jwks;
mod rsa;
pub(super) use additional_jwks::{merge_signing_public_jwks, validated_additional_signing_jwks};
pub(super) use rsa::rsa_public_jwk_from_private_der;
#[cfg(test)]
use rsa::rsa_public_jwk_from_private_pem;
use rsa::rsa_request_object_encryption_public_jwk_from_pkcs8_der;

#[derive(Clone)]
enum OidcSigningBackend {
    LocalPem {
        encoding_key: Arc<jsonwebtoken::EncodingKey>,
    },

    #[cfg(feature = "kms-aws")]
    AwsKms { signer: Arc<OidcAwsKmsSigner> },
}

impl OidcSigningBackend {
    fn kind(&self) -> &'static str {
        match self {
            Self::LocalPem { .. } => "local",

            #[cfg(feature = "kms-aws")]
            Self::AwsKms { .. } => "aws-kms",
        }
    }
}

#[derive(Clone)]
pub(super) struct OidcAdditionalPublicJwk {
    jwk: Jwk,
    expires_at_epoch_secs: Option<i64>,
}

impl OidcAdditionalPublicJwk {
    #[cfg(test)]
    fn persistent(jwk: Jwk) -> Self {
        Self {
            jwk,
            expires_at_epoch_secs: None,
        }
    }

    pub(super) fn retiring(jwk: Jwk, expires_at_epoch_secs: i64) -> Self {
        Self {
            jwk,
            expires_at_epoch_secs: Some(expires_at_epoch_secs),
        }
    }

    fn is_active_at(&self, now_epoch_secs: i64) -> bool {
        self.expires_at_epoch_secs
            .is_none_or(|expires_at| expires_at > now_epoch_secs)
    }
}

impl std::fmt::Debug for OidcAdditionalPublicJwk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcAdditionalPublicJwk")
            .field("kid", &self.jwk.kid)
            .field("expires_at_epoch_secs", &self.expires_at_epoch_secs)
            .finish()
    }
}

#[derive(Clone)]
pub struct OidcSigningKey {
    kid: String,
    backend: OidcSigningBackend,
    public_jwk: Jwk,
    additional_public_jwks: Vec<OidcAdditionalPublicJwk>,
}

impl std::fmt::Debug for OidcSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcSigningKey")
            .field("kid", &self.kid)
            .field("backend", &self.backend.kind())
            .field("public_jwk", &self.public_jwk)
            .field("additional_public_jwks", &self.additional_public_jwks)
            .finish_non_exhaustive()
    }
}

impl OidcSigningKey {
    /// # Errors
    ///
    /// Returns an error when the `kid` is invalid, the PEM cannot be parsed,
    /// or the RSA signing key cannot be initialized.
    #[cfg(test)]
    pub(crate) fn from_rsa_pem(kid: String, private_pem: &str) -> Result<Self, OidcConfigError> {
        validate_kid(&kid)?;

        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_pem.as_bytes())?;
        let public_jwk = rsa_public_jwk_from_private_pem(&kid, private_pem)?;

        Ok(Self {
            kid,
            backend: OidcSigningBackend::LocalPem {
                encoding_key: Arc::new(encoding_key),
            },
            public_jwk,
            additional_public_jwks: Vec::new(),
        })
    }

    /// # Errors
    ///
    /// Returns an error when the `kid` is invalid, the DER cannot initialize
    /// an RSA signing key, or the RSA public components cannot be derived.
    pub(crate) fn from_rsa_pkcs8_der(
        kid: String,
        private_der: &[u8],
    ) -> Result<Self, OidcConfigError> {
        validate_kid(&kid)?;

        // jsonwebtoken's DER entrypoint expects PKCS#1, while managed keys are PKCS#8.
        // Its PEM decoder performs the required PKCS#8-to-PKCS#1 unwrap before signing.
        let pkcs8_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", private_der.to_vec()));
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(pkcs8_pem.as_bytes())?;
        let public_jwk = rsa_public_jwk_from_private_der(&kid, private_der)?;

        Ok(Self {
            kid,
            backend: OidcSigningBackend::LocalPem {
                encoding_key: Arc::new(encoding_key),
            },
            public_jwk,
            additional_public_jwks: Vec::new(),
        })
    }

    #[cfg(feature = "kms-aws")]
    /// # Errors
    ///
    /// Returns an error when the KID is invalid, the AWS KMS signer cannot be
    /// initialized, or the public JWK cannot be derived from the configured KMS key.
    pub(crate) fn from_aws_kms(
        region: String,
        key_id: String,
        kid: String,
    ) -> Result<Self, OidcConfigError> {
        validate_kid(&kid)?;

        let signer = OidcAwsKmsSigner::new(region, key_id, kid.clone())
            .map_err(|err| OidcConfigError::AwsKmsSigningInit(err.to_string()))?;
        let public_jwk = signer.public_jwk().clone();

        Ok(Self {
            kid,
            backend: OidcSigningBackend::AwsKms {
                signer: Arc::new(signer),
            },
            public_jwk,
            additional_public_jwks: Vec::new(),
        })
    }

    #[cfg(feature = "kms-aws")]
    /// # Errors
    ///
    /// Returns an error when the KID is invalid, the AWS KMS signer cannot be
    /// initialized, or the public JWK cannot be derived from the configured KMS key.
    pub(crate) async fn from_aws_kms_async(
        region: String,
        key_id: String,
        kid: String,
    ) -> Result<Self, OidcConfigError> {
        validate_kid(&kid)?;

        let signer = OidcAwsKmsSigner::new_async(region, key_id, kid.clone())
            .await
            .map_err(|err| OidcConfigError::AwsKmsSigningInit(err.to_string()))?;
        let public_jwk = signer.public_jwk().clone();

        Ok(Self {
            kid,
            backend: OidcSigningBackend::AwsKms {
                signer: Arc::new(signer),
            },
            public_jwk,
            additional_public_jwks: Vec::new(),
        })
    }

    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    #[must_use]
    pub(super) fn public_jwk(&self) -> &Jwk {
        &self.public_jwk
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn local_encoding_key(&self) -> Option<&jsonwebtoken::EncodingKey> {
        match &self.backend {
            OidcSigningBackend::LocalPem { encoding_key } => Some(encoding_key.as_ref()),

            #[cfg(feature = "kms-aws")]
            OidcSigningBackend::AwsKms { .. } => None,
        }
    }

    /// # Errors
    ///
    /// Returns an error when the JWT cannot be serialized or signed.
    pub(crate) fn sign_rs256_jwt<T: serde::Serialize>(
        &self,
        claims: &T,
    ) -> Result<String, OidcSigningError> {
        match &self.backend {
            OidcSigningBackend::LocalPem { encoding_key } => {
                let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
                header.typ = Some("JWT".to_string());
                header.kid = Some(self.kid.clone());
                jsonwebtoken::encode(&header, claims, encoding_key.as_ref()).map_err(Into::into)
            }

            #[cfg(feature = "kms-aws")]
            OidcSigningBackend::AwsKms { signer } => signer
                .sign_rs256_jwt(claims)
                .map_err(|err| OidcSigningError::AwsKms(err.to_string())),
        }
    }

    /// # Errors
    ///
    /// Returns an error when the JWT cannot be serialized or signed.
    pub(crate) async fn sign_rs256_jwt_async<T: serde::Serialize>(
        &self,
        claims: &T,
    ) -> Result<String, OidcSigningError> {
        match &self.backend {
            OidcSigningBackend::LocalPem { encoding_key } => {
                let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
                header.typ = Some("JWT".to_string());
                header.kid = Some(self.kid.clone());
                jsonwebtoken::encode(&header, claims, encoding_key.as_ref()).map_err(Into::into)
            }

            #[cfg(feature = "kms-aws")]
            OidcSigningBackend::AwsKms { signer } => signer
                .sign_rs256_jwt_async(claims)
                .await
                .map_err(|err| OidcSigningError::AwsKms(err.to_string())),
        }
    }

    #[must_use]
    pub fn jwks(&self) -> Jwks {
        let additional = self.active_additional_public_jwks();
        let keys = merge_signing_public_jwks(&self.public_jwk, &self.kid, additional)
            .unwrap_or_else(|err| {
                tracing::error!(
                    error = %err,
                    "OIDC signing key JWKS assembly failed after validation"
                );
                vec![self.public_jwk.clone()]
            });
        Jwks { keys }
    }

    fn active_additional_public_jwks(&self) -> Vec<Jwk> {
        let now_epoch_secs = current_unix_epoch_secs();
        self.additional_public_jwks
            .iter()
            .filter(|key| key.is_active_at(now_epoch_secs))
            .map(|key| key.jwk.clone())
            .collect()
    }

    #[cfg(test)]
    pub(super) fn with_additional_public_jwks(
        mut self,
        additional: Vec<Jwk>,
    ) -> Result<Self, OidcConfigError> {
        self.additional_public_jwks =
            validated_additional_signing_jwks(additional, Some(self.kid.as_str()))?
                .into_iter()
                .map(OidcAdditionalPublicJwk::persistent)
                .collect();
        Ok(self)
    }

    pub(super) fn with_runtime_retiring_public_jwks(
        mut self,
        additional: Vec<OidcAdditionalPublicJwk>,
    ) -> Result<Self, OidcConfigError> {
        let jwks = additional
            .iter()
            .map(|additional| additional.jwk.clone())
            .collect::<Vec<_>>();
        validated_additional_signing_jwks(jwks, Some(self.kid.as_str()))?;
        self.additional_public_jwks = additional;
        Ok(self)
    }
}

#[derive(Clone)]
pub struct OidcRequestObjectEncryptionKey {
    kid: String,
    pkcs8_der: Arc<Vec<u8>>,
    public_jwk: Jwk,
}

impl std::fmt::Debug for OidcRequestObjectEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcRequestObjectEncryptionKey")
            .field("kid", &self.kid)
            .field("public_jwk", &self.public_jwk)
            .finish_non_exhaustive()
    }
}

impl OidcRequestObjectEncryptionKey {
    /// # Errors
    ///
    /// Returns an error when the `kid` is invalid, DER content is not a
    /// supported RSA PKCS#8 private key, or the public JWK cannot be derived.
    pub(crate) fn from_rsa_pkcs8_der(
        kid: String,
        private_der: &[u8],
    ) -> Result<Self, OidcConfigError> {
        if !kid_is_valid(&kid) {
            return Err(OidcConfigError::InvalidRequestObjectEncryptionKid);
        }

        let public_jwk =
            rsa_request_object_encryption_public_jwk_from_pkcs8_der(&kid, private_der)?;

        Ok(Self {
            kid,
            pkcs8_der: Arc::new(private_der.to_vec()),
            public_jwk,
        })
    }

    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    #[must_use]
    pub(crate) fn pkcs8_der(&self) -> &[u8] {
        self.pkcs8_der.as_ref()
    }

    #[must_use]
    pub(crate) fn public_jwk(&self) -> &Jwk {
        &self.public_jwk
    }
}

pub(super) fn validate_kid(kid: &str) -> Result<(), OidcConfigError> {
    if !kid_is_valid(kid) {
        return Err(OidcConfigError::InvalidSigningKid);
    }
    Ok(())
}

fn kid_is_valid(kid: &str) -> bool {
    !(kid.is_empty()
        || kid.len() > 128
        || !kid.is_ascii()
        || kid.chars().any(|c| c.is_ascii_whitespace()))
}

fn current_unix_epoch_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

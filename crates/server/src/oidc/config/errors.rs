#[derive(Debug, thiserror::Error)]
pub enum OidcConfigError {
    #[error("OIDC is enabled but issuer is not https: `{0}`")]
    IssuerNotHttps(String),

    #[error("OIDC is enabled but issuer is not a valid issuer URL: `{0}`")]
    IssuerInvalid(String),

    #[error("{field} has invalid policy value `{value}`: expected {expectation}")]
    InvalidNumericPolicy {
        field: &'static str,
        value: u64,
        expectation: &'static str,
    },

    #[error(
        "OIDC AWS KMS runtime-key provider requested but \
        aegaeon-server was built without the kms-aws feature"
    )]
    AwsKmsFeatureDisabled,

    #[error("OIDC AWS KMS runtime key provider_configuration.region must be set")]
    AwsKmsRegionMissing,

    #[error("failed to initialize OIDC AWS KMS signer: {0}")]
    AwsKmsSigningInit(String),

    #[error("failed to read OIDC signing key file: {0}")]
    SigningKeyRead(std::io::Error),

    #[error("failed to parse OIDC signing key PEM: {0}")]
    SigningKeyPem(#[from] pem::PemError),

    #[error("failed to parse OIDC signing key DER: {0}")]
    SigningKeyAsn1(#[from] simple_asn1::ASN1DecodeErr),

    #[error("OIDC signing key is not a supported RSA private key format")]
    SigningKeyUnsupportedFormat,

    #[error("failed to initialise RS256 signing key: {0}")]
    SigningKeyJwt(#[from] jsonwebtoken::errors::Error),

    #[error("OIDC signing kid must be non-empty ASCII without whitespace and <= 128 bytes")]
    InvalidSigningKid,

    #[error("failed to read OIDC request object encryption key file: {0}")]
    RequestObjectEncryptionKeyRead(std::io::Error),

    #[error("failed to parse OIDC request object encryption key PEM: {0}")]
    RequestObjectEncryptionKeyPem(pem::PemError),

    #[error("failed to parse OIDC request object encryption key DER: {0}")]
    RequestObjectEncryptionKeyAsn1(simple_asn1::ASN1DecodeErr),

    #[error("OIDC request object encryption key must be an unencrypted PKCS#8 RSA private key")]
    RequestObjectEncryptionKeyUnsupportedFormat,

    #[error(
        "OIDC request object encryption kid must be non-empty ASCII without whitespace and <= 128 bytes"
    )]
    InvalidRequestObjectEncryptionKid,

    #[error("OIDC request object encryption kid conflicts with an existing kid: {0}")]
    RequestObjectEncryptionKidConflicts(String),

    #[error("failed to read OIDC additional JWKS file: {0}")]
    AdditionalJwksRead(std::io::Error),

    #[error("invalid OIDC additional JWKS JSON: {0}")]
    AdditionalJwksJson(String),

    #[error("OIDC additional JWKS contains invalid kid: {0}")]
    AdditionalJwksInvalidKid(String),

    #[error("OIDC additional JWKS contains duplicate kid: {0}")]
    AdditionalJwksDuplicateKid(String),

    #[error("OIDC additional JWKS kid conflicts with active signing kid: {0}")]
    AdditionalJwksConflictingKid(String),

    #[error("OIDC additional JWKS contains unsupported key: {0}")]
    AdditionalJwksUnsupportedKey(String),

    #[error("OIDC additional JWKS failed internal consistency check: {0}")]
    AdditionalJwksInternalConsistency(String),

    #[error("OIDC management-database runtime keys are missing an ACTIVE {0} key")]
    ManagedKeyMissing(&'static str),

    #[error("OIDC managed key `{0}` has unsupported provider for this usage")]
    ManagedKeyUnsupportedProvider(String),

    #[error("OIDC managed key `{0}` key-handle decryption failed")]
    ManagedKeyHandleDecrypt(String),

    #[error("OIDC managed key `{0}` key-handle plaintext is not base64url PKCS#8 DER")]
    ManagedKeyHandleInvalidEncoding(String),

    #[error("OIDC managed key `{0}` public JWK does not match private key material")]
    ManagedPublicJwkMismatch(String),
}

#[derive(Debug, thiserror::Error)]
pub enum OidcSigningError {
    #[error("failed to sign RS256 JWT with local key: {0}")]
    Local(#[from] jsonwebtoken::errors::Error),

    #[cfg(feature = "kms-aws")]
    #[error("failed to sign RS256 JWT with AWS KMS: {0}")]
    AwsKms(String),
}
